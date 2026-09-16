rule Win_Trojan_Junkie_5
{
strings:
	$a0 = { b9f4012681344a264646e2f7 }


condition:
	$a0
}