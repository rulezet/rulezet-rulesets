rule Win_Trojan_Peed_344
{
strings:
	$a0 = { bd1656cd00eb3748b948110000ba20020200c1c2 }


condition:
	$a0
}