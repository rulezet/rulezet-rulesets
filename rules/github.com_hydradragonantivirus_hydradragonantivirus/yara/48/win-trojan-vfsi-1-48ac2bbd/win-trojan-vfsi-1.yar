rule Win_Trojan_VFSI_1
{
strings:
	$a0 = { 1fb8001aba8100cd21be0001ffe6 }


condition:
	$a0
}