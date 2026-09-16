rule Win_Trojan_Predator_14
{
strings:
	$a0 = { 02b1??fa8becbc????58f7d0d3c850eb01??4c4c4a75 }


condition:
	$a0
}