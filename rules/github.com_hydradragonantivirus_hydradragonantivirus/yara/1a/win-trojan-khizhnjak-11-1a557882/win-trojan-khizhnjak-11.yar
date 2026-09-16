rule Win_Trojan_Khizhnjak_11
{
strings:
	$a0 = { 26ba0001b9ea0190b440cd217219b90000ba0000b80042cd21720cbab802b90300b440cd21 }


condition:
	$a0
}