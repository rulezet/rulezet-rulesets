rule Win_Trojan_Leprosy_Seneca_1
{
strings:
	$a0 = { 0b7403eb1990b42acd2180fa19743eeb0d90b42ccd21 }


condition:
	$a0
}