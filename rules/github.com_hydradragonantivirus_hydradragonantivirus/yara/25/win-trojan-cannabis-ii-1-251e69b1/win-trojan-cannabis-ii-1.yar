rule Win_Trojan_Cannabis_II_1
{
strings:
	$a0 = { 04b440cd21803eb403017408b000e87400eb0a90 }


condition:
	$a0
}