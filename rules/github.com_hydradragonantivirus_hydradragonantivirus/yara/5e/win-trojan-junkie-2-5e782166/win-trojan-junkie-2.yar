rule Win_Trojan_Junkie_2
{
strings:
	$a0 = { 3f1cb9f4012681340b3c4646e2f7 }


condition:
	$a0
}