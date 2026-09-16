rule Win_Trojan_Sality_1050
{
strings:
	$a0 = { 02c55f??8a440500300780e9015e4e0f84??000000 }


condition:
	$a0
}