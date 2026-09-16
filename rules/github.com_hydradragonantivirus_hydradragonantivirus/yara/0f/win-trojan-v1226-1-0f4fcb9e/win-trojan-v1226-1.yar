rule Win_Trojan_V1226_1
{
strings:
	$a0 = { 3d8bf733d2b9540251335522474749 }


condition:
	$a0
}