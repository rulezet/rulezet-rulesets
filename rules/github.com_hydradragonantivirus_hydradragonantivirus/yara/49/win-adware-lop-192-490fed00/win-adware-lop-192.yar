rule Win_Adware_Lop_192
{
strings:
	$a0 = { daecfbc8b0ca8fc43ed0402093552020ac23533f3426a1a15e957c1f37ca3a2c3688cac425622f24a7acc57cba36b77f139a6deac059508cbac45bb9 }


condition:
	$a0
}