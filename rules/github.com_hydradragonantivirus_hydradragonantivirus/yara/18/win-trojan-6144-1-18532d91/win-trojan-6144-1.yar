rule Win_Trojan_6144_1
{
strings:
	$a0 = { a3005589e581ec0001c606bc0000b00050bf9ae21e57b83200509aad0aa3008dbe00ff165731c0509a250aa300 }


condition:
	$a0
}