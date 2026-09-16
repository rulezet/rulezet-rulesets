rule Win_Trojan_Exp_1
{
strings:
	$a0 = { 8ec033dbb81003b90200ba8001cd13b81103b90100ba8000cd13b80103b90100ba8001cd13c3 }


condition:
	$a0
}