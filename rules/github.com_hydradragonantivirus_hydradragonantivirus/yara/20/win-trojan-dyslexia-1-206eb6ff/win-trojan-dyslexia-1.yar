rule Win_Trojan_Dyslexia_1
{
strings:
	$a0 = { b4c0cd213d3412750e2e8b0e03011e07 }


condition:
	$a0
}