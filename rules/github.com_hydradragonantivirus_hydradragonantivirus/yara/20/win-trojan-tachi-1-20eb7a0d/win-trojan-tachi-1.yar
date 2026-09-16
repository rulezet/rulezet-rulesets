rule Win_Trojan_Tachi_1
{
strings:
	$a0 = { e882170000e805000000e9dc16000060e80e000000e8310a00008b64 }


condition:
	$a0
}