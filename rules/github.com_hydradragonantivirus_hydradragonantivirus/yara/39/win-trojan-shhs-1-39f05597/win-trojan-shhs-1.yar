rule Win_Trojan_SHHS_1
{
strings:
	$a0 = { a00601040d1400a20601c3bb3e01a006010ac0 }


condition:
	$a0
}