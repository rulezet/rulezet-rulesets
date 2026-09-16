rule Win_Trojan_Tchechen_4
{
strings:
	$a0 = { 5e83ee032e89b45302b8eb04ebfceacd80ec14cd21a102002d0003c41e0a002e899c4d022e8c844f02c7060a00 }


condition:
	$a0
}