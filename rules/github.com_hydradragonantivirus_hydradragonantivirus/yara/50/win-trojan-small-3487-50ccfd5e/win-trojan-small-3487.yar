rule Win_Trojan_Small_3487
{
strings:
	$a0 = { cceb56368648e5dafe808509e974bdf615e15f6a8bc543a1f420d870246e8cdefc3cb86ed45a2da71f41d1f5e045dab2f6888a87ef8c6cad348fb9936ecb0b9c29d1ce2ef22904b0fbd0e0e5aa1f }


condition:
	$a0
}