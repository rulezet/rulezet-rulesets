rule Win_Trojan_Moonlight_5
{
strings:
	$a0 = { 60e81b0000002377e537dc742bb03b0e7eae38 }

	$a1 = { 4e65774d6f226c69676824 }

	$a2 = { 5c556e696e7374616c6c5c436c616d4156 }


condition:
	$a0 and $a1 and $a2
}