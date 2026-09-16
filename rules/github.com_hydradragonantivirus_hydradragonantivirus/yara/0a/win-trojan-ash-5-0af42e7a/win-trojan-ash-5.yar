rule Win_Trojan_Ash_5
{
strings:
	$a0 = { 5d81ed0b01bf00018db60401b90400fcf3a4b41a8d }


condition:
	$a0
}