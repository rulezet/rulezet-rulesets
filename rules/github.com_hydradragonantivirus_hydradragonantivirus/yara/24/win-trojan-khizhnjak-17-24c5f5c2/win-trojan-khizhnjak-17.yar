rule Win_Trojan_Khizhnjak_17
{
strings:
	$a0 = { 2acd2180fe027c2880fa147c23b42ccd2180fd0b7c1abb0001ba8000b90100b80105cd13720ab8 }


condition:
	$a0
}