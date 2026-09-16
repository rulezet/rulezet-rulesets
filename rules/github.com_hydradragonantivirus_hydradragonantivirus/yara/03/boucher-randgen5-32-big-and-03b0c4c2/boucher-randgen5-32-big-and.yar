rule Boucher_randgen5__32_big_AND_
{
strings:
	$a0 = { 0000015d[0-20]000003b9[0-20]00000259[0-20]000002ef[0-20]0000022d[0-20]00000377 }

condition:
	$a0
}