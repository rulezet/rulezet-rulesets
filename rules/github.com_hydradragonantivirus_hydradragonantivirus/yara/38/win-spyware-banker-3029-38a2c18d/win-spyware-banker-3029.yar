rule Win_Spyware_Banker_3029
{
strings:
	$a0 = { 0e2a909bb1328795262464cc246f19eff851e8d0ee14b87a67da961b1cee16dc572d8fea0e829ee484bd6894bb }


condition:
	$a0
}