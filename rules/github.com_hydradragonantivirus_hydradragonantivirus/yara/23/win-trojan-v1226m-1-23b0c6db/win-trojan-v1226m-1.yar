rule Win_Trojan_V1226M_1
{
strings:
	$a0 = { 033d8bdf33d2b9540251335522474749 }


condition:
	$a0
}