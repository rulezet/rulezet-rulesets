rule Win_Trojan_Vini_1
{
strings:
	$a0 = { 36ff34582d6b0495e80000545e36ff34582d780495b85d5dcd213dfefe74538cc0488ec0268b1e030083eb339040 }


condition:
	$a0
}