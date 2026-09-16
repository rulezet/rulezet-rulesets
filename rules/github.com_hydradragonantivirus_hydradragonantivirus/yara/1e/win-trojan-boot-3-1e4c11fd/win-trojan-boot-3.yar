rule Win_Trojan_Boot_3
{
strings:
	$a0 = { bf7c33c0cd138ec00e1fbb007cb80102b500803ec30080907317b6018a16c3008a0ec400cd13 }


condition:
	$a0
}