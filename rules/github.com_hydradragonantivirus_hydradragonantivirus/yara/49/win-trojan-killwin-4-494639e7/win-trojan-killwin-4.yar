rule Win_Trojan_Killwin_4
{
strings:
	$a0 = { 63642077696e646f7773[0-8]64656c2073797374656d3332 }


condition:
	$a0
}