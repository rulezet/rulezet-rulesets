rule Win_Trojan_YCHV_1
{
strings:
	$a0 = { b80242cd2158240fb910002ac8b440cd21536800801fa116002ea31701a114002ea31501c7 }


condition:
	$a0
}