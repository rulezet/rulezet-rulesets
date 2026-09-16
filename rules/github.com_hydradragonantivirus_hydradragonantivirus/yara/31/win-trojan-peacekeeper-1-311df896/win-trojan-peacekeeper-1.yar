rule Win_Trojan_PeaceKeeper_1
{
strings:
	$a0 = { 5e83ee03eb47902e803e230b00740580fc0374062e }


condition:
	$a0
}