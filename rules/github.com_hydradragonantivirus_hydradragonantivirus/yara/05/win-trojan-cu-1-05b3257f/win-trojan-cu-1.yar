rule Win_Trojan_CU_1
{
strings:
	$a0 = { 4f2d03002ea31903050300b440ba0000b92004cd21b8004233c999cd21b440ba1803b90300cd21 }


condition:
	$a0
}