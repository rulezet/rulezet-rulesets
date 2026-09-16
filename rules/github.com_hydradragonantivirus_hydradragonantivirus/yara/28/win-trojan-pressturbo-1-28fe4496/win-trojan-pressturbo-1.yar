rule Win_Trojan_PressTurbo_1
{
strings:
	$a0 = { dd005589e5b814029acd02dd0081ec14029a7b0ddd008d7efc1657bf00000e579ae809dd00b8100050bf52001e }


condition:
	$a0
}