rule Win_Trojan_SillyE_4
{
strings:
	$a0 = { 5e83ee038cc02e03843d01051000502effb43b011e0e1fb41a32c0ba430103d6cd21505152 }


condition:
	$a0
}