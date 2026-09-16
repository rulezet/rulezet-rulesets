rule Win_Trojan_Judgement_1
{
strings:
	$a0 = { 5e4e4e4e56fc81c69000bfff0047a5a55eba4559b8010a80c4f0cd2133c08ec0bf????26817d034d50741eb98601[0-1]f3a4 }


condition:
	$a0
}