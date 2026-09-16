rule Win_Trojan_Small_4002
{
strings:
	$a0 = { ba0104ecba81c2ffff54458d8a38f000ff8d894414ff0052525131c050505454e812000000595a }


condition:
	$a0
}