rule Win_Trojan_R_86
{
strings:
	$a0 = { 2d465c9252bf9c04d1c757be4487d1c656be9a04d1c656be8c0656b880ca2d44c19050babd }


condition:
	$a0
}