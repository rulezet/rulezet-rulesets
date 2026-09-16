rule Win_Trojan_FraudLoad_35
{
strings:
	$a0 = { 5589e581ec3001000011c0 }


condition:
	$a0
}