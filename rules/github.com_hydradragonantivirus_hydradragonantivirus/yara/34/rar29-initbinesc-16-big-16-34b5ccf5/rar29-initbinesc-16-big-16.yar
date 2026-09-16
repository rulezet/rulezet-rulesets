rule Rar29_InitBinEsc__16_big_16_
{
strings:
	$a0 = { 3cdd1f3f59bf48f364a15abc66326051 }

condition:
	$a0
}