rule Win_Trojan_V21_1
{
strings:
	$a0 = { 18068d940001b440e809fd5a58597271 }


condition:
	$a0
}