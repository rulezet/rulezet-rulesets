rule Win_Trojan_Small_4143
{
strings:
	$a0 = { eb02cd2d8d1d99????fd81c36715650289dd8dbb7c07 }


condition:
	$a0
}