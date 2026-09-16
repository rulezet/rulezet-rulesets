rule Win_Trojan_Morphine_2
{
strings:
	$a0 = { abf6db85dbb25db83f8785dbb7e6d1c385dad1e085dbb255b8aa1232edb1f285c6b055fec2d1cb32e5b815ad85c1 }


condition:
	$a0
}