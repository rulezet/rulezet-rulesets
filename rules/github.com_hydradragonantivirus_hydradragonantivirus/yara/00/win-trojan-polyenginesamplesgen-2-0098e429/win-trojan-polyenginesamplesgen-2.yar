rule Win_Trojan_PolyEngineSamplesGen_2
{
strings:
	$a0 = { b409e800005a83c208cd21cd2041742074686520776f7264206f6620746865206461726b206a7564 }


condition:
	$a0
}