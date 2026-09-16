rule Win_Trojan_Trivial_369
{
strings:
	$a0 = { b000b44eba4a01cd21e90c00b43ecd21b44fcd210ac07531b8023dba9e00cd218bd8b43fb90200ba5401cd21813e5401 }


condition:
	$a0
}