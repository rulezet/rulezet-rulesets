rule Win_Trojan_Flavour_1
{
strings:
	$a0 = { fdb8008fcd213d8f00750f81c61c01bf00011657fca5a5161fcb33ffb452cd21268b5ffe8ec3 }


condition:
	$a0
}