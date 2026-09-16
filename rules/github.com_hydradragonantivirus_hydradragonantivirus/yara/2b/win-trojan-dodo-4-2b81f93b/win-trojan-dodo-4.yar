rule Win_Trojan_Dodo_4
{
strings:
	$a0 = { ba06cd2180fcab7502eb31b82135cd21b810001e065007 }


condition:
	$a0
}