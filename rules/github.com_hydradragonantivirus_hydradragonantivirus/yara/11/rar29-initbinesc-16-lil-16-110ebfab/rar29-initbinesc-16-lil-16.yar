rule Rar29_InitBinEsc__16_lil_16_
{
strings:
	$a0 = { dd3c3f1fbf59f348a164bc5a32665160 }

condition:
	$a0
}