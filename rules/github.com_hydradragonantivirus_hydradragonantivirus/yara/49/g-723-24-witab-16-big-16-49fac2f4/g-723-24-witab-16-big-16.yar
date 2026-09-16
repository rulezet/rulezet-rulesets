rule G_723_24__witab__16_big_16_
{
strings:
	$a0 = { FF8003C0112048C048C0112003C0FF80 }

condition:
	$a0
}