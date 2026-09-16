rule Speed_Challenge_files_decoder__8_byt_41_
{
strings:
	$a0 = { cf203af7127ef19ff19ab16bac484af8411f47b42f2dd1377fead1d7056b5576e4d8359f5020f6d298 }

condition:
	$a0
}