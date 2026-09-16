rule Win_Trojan_Peed_302
{
strings:
	$a0 = { 64a1180000008b40308b401033ff6639783874788d45d?897dd?e8????00006a04be0030 }


condition:
	$a0
}