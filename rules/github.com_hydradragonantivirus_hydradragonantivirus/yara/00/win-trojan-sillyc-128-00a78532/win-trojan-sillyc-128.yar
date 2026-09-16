rule Win_Trojan_SillyC_128
{
strings:
	$a0 = { bd00008d96f601b41acd21b90000b44e8b96eb01528b96ed01528d96e501cd217209e92c00b44fcd217326ba8000b41a }


condition:
	$a0
}