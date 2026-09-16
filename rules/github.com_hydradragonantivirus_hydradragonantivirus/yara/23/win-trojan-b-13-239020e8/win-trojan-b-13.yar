rule Win_Trojan_B_13
{
strings:
	$a0 = { 25cd218cc88ed88ec058bb000153c3 }


condition:
	$a0
}