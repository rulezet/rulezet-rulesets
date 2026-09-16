rule Win_Trojan_Flux_17
{
strings:
	$a0 = { 948dd9d4c19bf463[0-1]155efab7[0-5]dd5dc0[0-4]0636[0-1]bd5a37596d446f7a[0-1]b909d054d124a39b[0-1]31d2e3d3e1783aaa[0-1]cb2f21 }


condition:
	$a0
}