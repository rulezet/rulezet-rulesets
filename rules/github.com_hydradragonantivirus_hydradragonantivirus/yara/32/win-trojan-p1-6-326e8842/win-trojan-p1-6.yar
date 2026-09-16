rule Win_Trojan_P1_6
{
strings:
	$a0 = { 75638cd83b460c755c8b760aac3ccc }


condition:
	$a0
}