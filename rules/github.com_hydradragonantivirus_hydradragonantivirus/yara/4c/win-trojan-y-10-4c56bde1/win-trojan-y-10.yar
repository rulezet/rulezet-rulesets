rule Win_Trojan_Y_10
{
strings:
	$a0 = { b90100ba8000bb1302cd13b80102fec4505141cd1389dfb8eb2bfcabe831005958cd13eaf0ffffff0e1fbe1204 }


condition:
	$a0
}