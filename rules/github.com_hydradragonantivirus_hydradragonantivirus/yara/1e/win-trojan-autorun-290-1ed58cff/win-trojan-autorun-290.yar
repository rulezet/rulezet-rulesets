rule Win_Trojan_Autorun_290
{
strings:
	$a0 = { d4795e5aa9b2049483f038491d26b3d96b9079852f40bb4a75a242c29e9326b9bc4c5cda0cd9e4f75ef7fc0a957b078ade11fbfc0fdf3c7dd29fad140e6202f04b9fdbbde4bef0e700decc564579dced }


condition:
	$a0
}