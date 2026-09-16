rule Win_Trojan_L_15
{
strings:
	$a0 = { 268a0289c080ec00340088db26880283c20083c30046 }


condition:
	$a0
}