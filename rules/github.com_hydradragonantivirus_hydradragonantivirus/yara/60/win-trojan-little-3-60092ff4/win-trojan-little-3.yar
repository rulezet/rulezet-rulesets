rule Win_Trojan_Little_3
{
strings:
	$a0 = { 33c98d162701cd21b8023dba9e00cd21b92c008d160001b440cd21b43ecd21b44fcd2173e3 }


condition:
	$a0
}