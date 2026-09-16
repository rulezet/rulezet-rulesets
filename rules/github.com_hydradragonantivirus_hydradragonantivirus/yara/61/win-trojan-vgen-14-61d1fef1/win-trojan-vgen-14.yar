rule Win_Trojan_Vgen_14
{
strings:
	$a0 = { 5152061e5756e800005bbea55abfaa550e0781c3e80381fbe8037303e9820053b80102ba0000b90100cd135b7308 }


condition:
	$a0
}