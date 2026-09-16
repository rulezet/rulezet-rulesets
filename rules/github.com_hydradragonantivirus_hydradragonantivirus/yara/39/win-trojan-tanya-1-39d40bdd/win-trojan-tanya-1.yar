rule Win_Trojan_Tanya_1
{
strings:
	$a0 = { e800005b83eb03be0000b9d0070e1fb05f304021c0c00387cb9087cb }


condition:
	$a0
}