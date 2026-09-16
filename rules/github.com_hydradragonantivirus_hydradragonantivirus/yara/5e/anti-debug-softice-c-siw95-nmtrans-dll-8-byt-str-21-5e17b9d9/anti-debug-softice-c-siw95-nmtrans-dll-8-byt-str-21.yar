rule anti_debug__Softice_C__siw95_nmtrans_dll__8_byt_STR_21_
{
strings:
	$a0 = { 433a5c73697739355c6e6d7472616e732e646c6c00 }

condition:
	$a0
}