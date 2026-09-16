rule Win_Trojan_VGEN_12
{
strings:
	$a0 = { 8ec0bf00018bf70e575706b136f2a5b8170150cb1e07be6c015fb5fef2a40e1fb44eba6601cd217237061fba9e }


condition:
	$a0
}