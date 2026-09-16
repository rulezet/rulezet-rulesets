rule Win_Trojan_Boot_14
{
strings:
	$a0 = { e661b020e62058cf01fabe007dbfa0040e1f0e07b92000fcf3a5c43624008936b8048c06ba04 }


condition:
	$a0
}