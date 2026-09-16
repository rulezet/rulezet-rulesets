rule Win_Trojan_Junkie_1
{
strings:
	$a0 = { be7f??b9f401268134????4646e2f7 }


condition:
	$a0
}