rule Win_Trojan_Tiny_14
{
strings:
	$a0 = { b063aab06faab06daab000aacd217301c3b8013dba9e00cd2193b440b137ba0001cd21b43ecd21 }


condition:
	$a0
}