rule Win_Trojan_Sandman_1
{
strings:
	$a0 = { 4000ff55d4bf00204000576a01509646a4803e2275fafe46fec60700ff55dc556848104000 }


condition:
	$a0
}