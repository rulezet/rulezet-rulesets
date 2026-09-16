rule Win_Trojan_Waledac_28
{
strings:
	$a0 = { 03c181c2d2000000090d003d4500ff15f410400083 }


condition:
	$a0
}