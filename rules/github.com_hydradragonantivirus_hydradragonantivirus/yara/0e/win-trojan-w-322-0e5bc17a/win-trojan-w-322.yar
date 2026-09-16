rule Win_Trojan_W_322
{
strings:
	$a0 = { b912f7bf90570f014c24fe5fdf2f50041cabab58ff77028f47facd00df7f }


condition:
	$a0
}