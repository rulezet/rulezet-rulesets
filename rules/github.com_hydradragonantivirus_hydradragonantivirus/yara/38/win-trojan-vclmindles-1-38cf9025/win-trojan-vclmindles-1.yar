rule Win_Trojan_VCLMindles_1
{
strings:
	$a0 = { e90000b9eb09b805feebfc80c43bebf41e2bc050b42acd213c00756eb8013332d2cd21b94600be1802bf5e028a04a2a4028036a40201a0a40288054647e2ed803e1002 }


condition:
	$a0
}