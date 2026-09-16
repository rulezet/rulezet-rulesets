rule Win_Trojan_Astra_4
{
strings:
	$a0 = { 8d00b90200b4409c2eff1ece0133c92e8b168d0081c2f301b800429c2eff1ece01b90000b4409c }


condition:
	$a0
}