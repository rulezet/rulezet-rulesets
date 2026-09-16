rule Win_Trojan_W_136
{
strings:
	$a0 = { 6a00535689442424ffd585c07532566804010000ff15 }


condition:
	$a0
}