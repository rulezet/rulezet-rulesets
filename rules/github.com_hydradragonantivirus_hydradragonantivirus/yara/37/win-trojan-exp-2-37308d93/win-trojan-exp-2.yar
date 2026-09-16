rule Win_Trojan_Exp_2
{
strings:
	$a0 = { db00ac3cff74063204cd29ebf5c333c08ec033dbb81003b90200ba8001cd13b81103b90100ba8000cd13b80103b901 }


condition:
	$a0
}