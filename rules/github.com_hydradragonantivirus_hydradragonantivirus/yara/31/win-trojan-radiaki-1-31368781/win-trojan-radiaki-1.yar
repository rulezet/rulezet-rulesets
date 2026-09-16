rule Win_Trojan_Radiaki_1
{
strings:
	$a0 = { 81ed0b01bf00018db6b20257a4a5b41a8d961c03cd21b447b2008db6dc02cd21b82435cd21899edd018c86df01b4 }


condition:
	$a0
}