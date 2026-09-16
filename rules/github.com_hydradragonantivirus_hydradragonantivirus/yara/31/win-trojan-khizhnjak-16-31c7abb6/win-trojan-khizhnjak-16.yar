rule Win_Trojan_Khizhnjak_16
{
strings:
	$a0 = { 03cd21b42acd2180fe057d23b42ccd2180fd01751abb0001ba8000b90100b80105cd13720a }


condition:
	$a0
}