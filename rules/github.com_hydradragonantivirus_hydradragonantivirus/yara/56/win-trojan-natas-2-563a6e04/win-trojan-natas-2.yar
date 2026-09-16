rule Win_Trojan_Natas_2
{
strings:
	$a0 = { 31d281f20adc8d2e8ca381c713e587ceffc845f98bf3f581ddffff0bca3196fa70f881d2243cfd40488bfb8bcd74048bf675db }


condition:
	$a0
}