rule Win_Trojan_Bifrose_204
{
strings:
	$a0 = { a336e027f2ad5410a1e58aa8f799cc654d08eb67f2ffe16656e01a134b45a2e54cac45155df5013cff3ec612498d9740239f85bfafaa983bfbce70c8f66a1795c70173bea6caada6548270713e30 }


condition:
	$a0
}