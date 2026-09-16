rule G_723_24__witab__16_lil_16_
{
strings:
	$a0 = { 80FFC0032011C048C0482011C00380FF }

condition:
	$a0
}