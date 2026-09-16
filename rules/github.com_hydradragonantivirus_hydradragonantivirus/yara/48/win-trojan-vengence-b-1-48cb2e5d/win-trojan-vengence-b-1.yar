rule Win_Trojan_Vengence_B_1
{
strings:
	$a0 = { ba6801b44ecd217259ba9e0089160202b8023dcd217245a3 }


condition:
	$a0
}