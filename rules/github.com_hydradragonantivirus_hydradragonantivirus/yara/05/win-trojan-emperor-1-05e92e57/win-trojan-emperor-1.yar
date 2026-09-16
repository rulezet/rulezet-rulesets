rule Win_Trojan_Emperor_1
{
strings:
	$a0 = { 0d0020509d9c58a900207505b8ff4ccd210f21f824f90f23f80f21f066a90040000075600e5b }


condition:
	$a0
}