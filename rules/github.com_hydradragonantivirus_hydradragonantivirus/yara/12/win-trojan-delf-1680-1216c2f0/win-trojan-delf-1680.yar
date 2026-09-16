rule Win_Trojan_Delf_1680
{
strings:
	$a0 = { 9c60e8000000005d83ed078d8530fcffff8038010f8442020000c600018bd52b95c4fbffff8995c4fbff }


condition:
	$a0
}