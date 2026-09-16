rule Win_Trojan_Lambrusco_1
{
strings:
	$a0 = { b440b9d600ba0001cd21be6f01ac0ac07404cd29ebf7b409ba8001803eb001007403ba9201cd21 }


condition:
	$a0
}