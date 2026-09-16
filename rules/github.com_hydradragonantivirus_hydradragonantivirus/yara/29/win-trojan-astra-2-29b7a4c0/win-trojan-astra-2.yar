rule Win_Trojan_Astra_2
{
strings:
	$a0 = { 8916880033c9b800429c2eff1eb501b9b90133d2b4409c2eff1eb50133c9ba0800b800429c2eff }


condition:
	$a0
}