rule Win_Trojan_IceBorn_1
{
strings:
	$a0 = { e90d0000cd209f8e062e069e5e5f5a59 }

	$a1 = { 63bff1dd197b2cbbdc137bdc157bdd247b03dd177bdd167b }


condition:
	$a0 and $a1
}