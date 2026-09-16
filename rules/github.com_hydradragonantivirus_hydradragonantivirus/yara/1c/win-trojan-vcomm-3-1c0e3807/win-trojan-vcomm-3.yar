rule Win_Trojan_VComm_3
{
strings:
	$a0 = { cd21e83e00a19a02a33502a19c02a333021e }


condition:
	$a0
}