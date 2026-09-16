rule Win_Trojan_Grog_2
{
strings:
	$a0 = { 3d0e1fba2004cd217305e9ee0059c38be893b90200ba }


condition:
	$a0
}