rule Win_Trojan_Nabshell_2
{
strings:
	$a0 = { 8d85e4f6ffff6a0a50ff75fce867c1ffff8d85e4f6ffff68c493400050e85004000083c41485c00f85c80100008d85e4f6ffff50e80fc7ffff598d45f4508d85e4feffff50ff15e8704000e820c0ffff }


condition:
	$a0
}