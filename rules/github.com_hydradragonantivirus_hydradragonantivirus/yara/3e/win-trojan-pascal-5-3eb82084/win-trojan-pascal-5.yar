rule Win_Trojan_Pascal_5
{
strings:
	$a0 = { 01b82425ba5a03cd21b41aba2601cd }


condition:
	$a0
}