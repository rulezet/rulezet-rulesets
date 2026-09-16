rule Win_Trojan_Tracer_1
{
strings:
	$a0 = { 9090e800005dbb1201faeb00c6070beb0190e800005881ed0701eb0c90e80000582d0701b44ccd21608b9e17032e }


condition:
	$a0
}