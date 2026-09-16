rule Win_Trojan_Stoned_65
{
strings:
	$a0 = { b9450189f7ac30d8aa4975f9c331c08ed8b372be157ce8e7ffe91cff }


condition:
	$a0
}