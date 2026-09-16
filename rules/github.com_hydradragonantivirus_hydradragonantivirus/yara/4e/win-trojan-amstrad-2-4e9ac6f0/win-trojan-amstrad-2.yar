rule Win_Trojan_Amstrad_2
{
strings:
	$a0 = { 0e0100002e8c0610012eff2e0e01 }


condition:
	$a0
}