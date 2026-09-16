rule Win_Trojan_Trivial_144
{
strings:
	$a0 = { 4eba1a00cd21b8023dba9e00cd21b74093ba0000b11ecd21c32a2e2a00 }


condition:
	$a0
}