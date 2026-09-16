rule Win_Trojan_Virdem_6
{
strings:
	$a0 = { 7409b44fcd2172ac4b75f7b42fcd }


condition:
	$a0
}