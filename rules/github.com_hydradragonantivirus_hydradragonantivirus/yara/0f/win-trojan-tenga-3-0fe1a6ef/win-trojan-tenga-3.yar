rule Win_Trojan_Tenga_3
{
strings:
	$a0 = { 558bec83ec4456ff15442040008bf08a063c2275148a46 }

	$a1 = { 474554202f7678392f646c2e657865 }

	$a2 = { 77696e6c6f676f6e2e657865 }


condition:
	$a0 and $a1 and $a2
}