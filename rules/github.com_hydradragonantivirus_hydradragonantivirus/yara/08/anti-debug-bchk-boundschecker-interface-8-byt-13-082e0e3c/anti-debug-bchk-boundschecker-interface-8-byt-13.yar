rule anti_debug__BCHK_BoundsChecker_interface__8_byt_13_
{
strings:
	$a0 = { bd4b48434266b80400cd033c04 }

condition:
	$a0
}