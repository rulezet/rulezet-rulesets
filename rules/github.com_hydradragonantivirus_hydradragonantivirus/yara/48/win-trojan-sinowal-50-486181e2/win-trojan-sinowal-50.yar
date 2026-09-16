rule Win_Trojan_Sinowal_50
{
strings:
	$a0 = { 558bec51ff7508e8a058ffff8b4d0c8b018b50188b4020a3[0-36]45fc6894ab01005151515150 }


condition:
	$a0
}