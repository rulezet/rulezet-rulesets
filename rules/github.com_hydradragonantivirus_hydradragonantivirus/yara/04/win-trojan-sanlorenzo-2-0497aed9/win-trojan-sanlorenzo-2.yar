rule Win_Trojan_SanLorenzo_2
{
strings:
	$a0 = { cc5d81ed0301b000e82e05ba1f058bca8db61d01b44ccd21e2fa }


condition:
	$a0
}