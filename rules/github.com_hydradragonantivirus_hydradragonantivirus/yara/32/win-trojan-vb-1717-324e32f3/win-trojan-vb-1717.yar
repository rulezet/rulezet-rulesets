rule Win_Trojan_VB_1717
{
strings:
	$a0 = { 65706f73697461626c6500f40100000c1c4000000000006012 }


condition:
	$a0
}