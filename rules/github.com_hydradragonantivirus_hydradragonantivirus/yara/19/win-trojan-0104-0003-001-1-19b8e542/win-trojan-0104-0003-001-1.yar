rule Win_Trojan__0104_0003_001_1
{
strings:
	$a0 = { 0957b9a2098b16a502b006e8f8005ab440cd21e80d00b91800baa702b440cd21e952ff32c0eb02 }


condition:
	$a0
}