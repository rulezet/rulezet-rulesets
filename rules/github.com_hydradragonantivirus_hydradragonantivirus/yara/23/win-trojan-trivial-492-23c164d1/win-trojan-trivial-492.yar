rule Win_Trojan_Trivial_492
{
strings:
	$a0 = { 21b43bba1402cd21b43bba1002cd21b44eba1c02cd21b8013dba9e00cd2193b440b92201ba0001cd21 }


condition:
	$a0
}