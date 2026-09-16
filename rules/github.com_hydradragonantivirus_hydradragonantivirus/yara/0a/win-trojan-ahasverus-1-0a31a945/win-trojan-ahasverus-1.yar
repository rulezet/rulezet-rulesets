rule Win_Trojan_Ahasverus_1
{
strings:
	$a0 = { ffe93403f30367037d0305009c2eff1e0300c3231a5b6514a8dadadf2d105b6515f87e11fb582d102d6515f87411 }


condition:
	$a0
}