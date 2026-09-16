rule Win_Trojan_Diamond_3
{
strings:
	$a0 = { b440cd2172043bc17401f9c39c0e }


condition:
	$a0
}