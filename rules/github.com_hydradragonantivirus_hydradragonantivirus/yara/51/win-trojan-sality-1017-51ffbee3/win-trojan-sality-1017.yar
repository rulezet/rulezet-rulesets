rule Win_Trojan_Sality_1017
{
strings:
	$a0 = { 60e8530000008dbd0010400068????????033c248bf768301040009bdbe355db04248bc7db442404dec1db1c24 }


condition:
	$a0
}