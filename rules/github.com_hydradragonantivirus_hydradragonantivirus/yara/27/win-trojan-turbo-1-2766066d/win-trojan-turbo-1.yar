rule Win_Trojan_Turbo_1
{
strings:
	$a0 = { 890e02018cd88ec05958bb0001ffe3a1 }


condition:
	$a0
}