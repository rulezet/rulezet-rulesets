rule Win_Trojan_L_41
{
strings:
	$a0 = { 2701be3901b99c0131044646e2fac32e813e5d002d3f7509b409ba4202cd21cd20b409ba0502cd21b401b5cdb10ecd }


condition:
	$a0
}