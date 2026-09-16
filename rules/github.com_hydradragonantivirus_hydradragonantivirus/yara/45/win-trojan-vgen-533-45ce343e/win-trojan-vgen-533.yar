rule Win_Trojan_VGEN_533
{
strings:
	$a0 = { c606ff000fc606f80000c706fd00ffff813e0000cd206a001f7568b4fbcd137315e8c0000e0e07e8 }


condition:
	$a0
}