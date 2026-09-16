rule Win_Trojan_Diamond_11
{
strings:
	$a0 = { 40cd2172043bc17401f9c39c0ee8 }


condition:
	$a0
}