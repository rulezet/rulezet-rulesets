rule Win_Trojan_Khizhnjak_15
{
strings:
	$a0 = { 01b92c02908b1e3403b440cd217245b90000ba00 }


condition:
	$a0
}