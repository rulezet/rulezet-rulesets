rule Win_Trojan_Brian_1
{
strings:
	$a0 = { a3005589e581ec0202c6064400008dbe00ff165731c0509a1e0aa300bf25221e57b8ff00509a8e05a3008dbe00 }


condition:
	$a0
}