rule Win_Trojan_Exile_1
{
strings:
	$a0 = { 100726f6066c037c7534b10233d28ac2cd26ba29018bea0000003e8076004445e2f8b409cd21eb }


condition:
	$a0
}