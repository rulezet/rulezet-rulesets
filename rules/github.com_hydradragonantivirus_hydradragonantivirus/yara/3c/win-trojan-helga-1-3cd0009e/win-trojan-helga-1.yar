rule Win_Trojan_Helga_1
{
strings:
	$a0 = { 029052528a773b9032f488773b9043e2f3c360b42ccd2133ca32e9886d10e8 }


condition:
	$a0
}