rule Win_Trojan_Trivial_161
{
strings:
	$a0 = { b44eba1901cd21b8023dba9e00cd2193b440b120ba0001cd21 }


condition:
	$a0
}