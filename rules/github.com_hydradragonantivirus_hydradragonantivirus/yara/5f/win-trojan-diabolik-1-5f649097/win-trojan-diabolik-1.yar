rule Win_Trojan_Diabolik_1
{
strings:
	$a0 = { b405b500b100b600b200cd13b405b500 }


condition:
	$a0
}