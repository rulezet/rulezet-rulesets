rule Win_Trojan_AOD_1
{
strings:
	$a0 = { 8b86820131074343e2fa5bc3e8e9ffb4408d960600b98101cd21e8dbffc37968 }


condition:
	$a0
}