rule Win_Trojan_Exeheader_3
{
strings:
	$a0 = { 0e1fba0600b440cd7833d23bea740f8bcd03c903cd }


condition:
	$a0
}