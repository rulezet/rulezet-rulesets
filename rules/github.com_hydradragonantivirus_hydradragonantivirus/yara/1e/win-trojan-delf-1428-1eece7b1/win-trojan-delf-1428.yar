rule Win_Trojan_Delf_1428
{
strings:
	$a0 = { 68bf39410064ff306489206a01e82a86ffff6a01e82386ffff6a01e81c86ffff6a01e81586ffff6a01e80e86ffff6a01e80786ffff6a01e80086ffff6a01e8f985ffff6a01e8f285ffff6a01e8eb85ffff }


condition:
	$a0
}