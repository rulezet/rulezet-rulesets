rule Win_Trojan_Damned_1
{
strings:
	$a0 = { bb4c53b94d41cd213d4b4f745306b82135cd212e89 }


condition:
	$a0
}