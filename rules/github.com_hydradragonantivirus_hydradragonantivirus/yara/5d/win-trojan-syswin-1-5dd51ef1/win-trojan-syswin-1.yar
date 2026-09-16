rule Win_Trojan_Syswin_1
{
strings:
	$a0 = { 85c075578d55f88bc3e894c1fdff8d45f8ba1c9a4200e8139cfdff8b45f8e8a7bffdff84c07434837dfc00751868049a4200b9e8994200baf49942008bc6e84bd6ffffeb16 }


condition:
	$a0
}