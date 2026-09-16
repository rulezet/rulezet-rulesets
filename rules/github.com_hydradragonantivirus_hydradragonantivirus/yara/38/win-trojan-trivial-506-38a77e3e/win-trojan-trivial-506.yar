rule Win_Trojan_Trivial_506
{
strings:
	$a0 = { ba2501b44ecd21e81f00ba1f01b44ecd21e81500b409ba4b01cd21cd202a2e696e69002a2e65786500721db8013dba9e00cd2193ba0001b9b000b440cd21b43ecd21b44fcd2173e1c3 }


condition:
	$a0
}