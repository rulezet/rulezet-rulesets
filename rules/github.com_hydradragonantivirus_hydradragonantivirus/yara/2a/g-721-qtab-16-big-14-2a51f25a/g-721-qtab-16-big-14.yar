rule G_721_qtab__16_big_14_
{
strings:
	$a0 = { FF84005000B200F6012C015D0190 }

condition:
	$a0
}