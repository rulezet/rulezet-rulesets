rule Win_Trojan_EraseHDD_3
{
strings:
	$a0 = { 1335cd21891e1d018c061f010e07bb2801b90200ba8000b801039c9a00000000fec675f342ebf0 }


condition:
	$a0
}