rule Win_Trojan_Batman3_1
{
strings:
	$a0 = { 3f2e8b1e1201cdf1c3b4402e8b1e1201cdf1c3b000cf2e803e4f01207509e861012ec6064f01 }


condition:
	$a0
}