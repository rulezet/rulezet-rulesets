rule Win_Trojan_Mikrob_2
{
strings:
	$a0 = { 6f721e60b82812bd024233c999cd2f611fb4408d56fdb9ce0090cd213e8b86e7002d04003e8986 }


condition:
	$a0
}