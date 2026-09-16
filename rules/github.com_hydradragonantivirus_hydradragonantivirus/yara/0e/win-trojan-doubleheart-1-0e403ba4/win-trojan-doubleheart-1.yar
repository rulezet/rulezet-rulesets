rule Win_Trojan_Doubleheart_1
{
strings:
	$a0 = { 01a3d801c706e60193192bc92bd28b1ef201b80042cd21720ebad401b918008b1ef201b440cd21 }


condition:
	$a0
}