rule Win_Trojan_Philis_119
{
strings:
	$a0 = { 565e535383c404812c244b4d2100578b5c240483c408684b4d2100 }


condition:
	$a0
}