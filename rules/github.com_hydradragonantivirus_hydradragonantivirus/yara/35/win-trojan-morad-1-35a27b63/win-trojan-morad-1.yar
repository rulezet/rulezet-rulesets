rule Win_Trojan_Morad_1
{
strings:
	$a0 = { 40bd30f98b5e00b98c04bd32f98b560081ea8c04cd217227b457b001bd30f98b5e00bd16f98b4e }


condition:
	$a0
}