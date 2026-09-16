rule Win_Trojan_Deicide_11
{
strings:
	$a0 = { 19cd21a25502a26002b447b200bea5 }


condition:
	$a0
}