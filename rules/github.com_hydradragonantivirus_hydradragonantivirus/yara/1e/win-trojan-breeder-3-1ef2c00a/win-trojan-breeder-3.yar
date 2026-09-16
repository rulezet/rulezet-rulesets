rule Win_Trojan_Breeder_3
{
strings:
	$a0 = { 1a722180fe02751cb42ccd2183fa3c7f138d7607fc }


condition:
	$a0
}