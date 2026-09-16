rule Win_Trojan_QQPass_12
{
strings:
	$a0 = { 68944440008d45f8ba28874000b905010000e8fbf3ffff8b45f88d55fce8e80300008b45fce8f8f5ffff50e8fafdffff }


condition:
	$a0
}