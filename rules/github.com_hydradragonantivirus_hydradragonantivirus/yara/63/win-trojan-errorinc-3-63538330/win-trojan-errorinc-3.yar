rule Win_Trojan_ErrorInc_3
{
strings:
	$a0 = { 0203d5b90700b440cd2133c933d2b80242cd21e86d00e8b5008bd581c20701b9d101b440cd21 }


condition:
	$a0
}