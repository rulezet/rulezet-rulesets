rule Win_Trojan_Uranus_1
{
strings:
	$a0 = { 817f13400b754b26817f2b504b74432681bf6b015355743a06b80102fec450b90c4fb601cd1373 }


condition:
	$a0
}