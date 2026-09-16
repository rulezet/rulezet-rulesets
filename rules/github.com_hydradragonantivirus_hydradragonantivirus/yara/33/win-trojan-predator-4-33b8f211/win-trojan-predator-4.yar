rule Win_Trojan_Predator_4
{
strings:
	$a0 = { 0c02b100fa8becbc341258f7d0d3c850eb01124c4c4a75 }


condition:
	$a0
}