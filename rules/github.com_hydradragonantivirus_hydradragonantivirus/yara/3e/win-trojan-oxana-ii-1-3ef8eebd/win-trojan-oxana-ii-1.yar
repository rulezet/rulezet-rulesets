rule Win_Trojan_Oxana_II_1
{
strings:
	$a0 = { 1e060e1f8cc00510000106980101069a01b84242cd213c037514071f612e8e169a012e8b269c0133ed2eff2e9601b8 }


condition:
	$a0
}