rule Win_Trojan_Tchechen_3
{
strings:
	$a0 = { 07e800005e83ee032e89b49000b8ebf0cd21a102002d0003c41e0a002e899c8b002e8c848d00c7060a004600a30c }


condition:
	$a0
}