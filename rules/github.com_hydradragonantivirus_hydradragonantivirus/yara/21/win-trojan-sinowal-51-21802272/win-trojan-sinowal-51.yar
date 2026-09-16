rule Win_Trojan_Sinowal_51
{
strings:
	$a0 = { 558bec51ff7508e8[0-1]58ffff8b4d0c8b018b50188b4020a3 }

	$a1 = { 45fc68[0-1]ab01005151515150 }


condition:
	$a0 and $a1
}