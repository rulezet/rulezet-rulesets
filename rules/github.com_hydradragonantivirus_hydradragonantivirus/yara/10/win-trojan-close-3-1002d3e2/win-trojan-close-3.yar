rule Win_Trojan_Close_3
{
strings:
	$a0 = { 0f1f832c311e8bce36fe070726836cff31268e44ff33f6 }


condition:
	$a0
}