rule Win_Trojan_PCBB_3
{
strings:
	$a0 = { b9700689e581460012005e468074ffbae2f9 }


condition:
	$a0
}