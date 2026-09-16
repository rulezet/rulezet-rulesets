rule Win_Trojan_Gen_25
{
strings:
	$a0 = { 1a008bd181c200018b0db43fcd2133c98bd1b80042cd2159030dba0001b440cd211fb80057cd21 }


condition:
	$a0
}