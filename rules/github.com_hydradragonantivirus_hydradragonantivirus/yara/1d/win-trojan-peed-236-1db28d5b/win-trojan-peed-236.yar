rule Win_Trojan_Peed_236
{
strings:
	$a0 = { beff74540f85ff92732a5589e551418b7d1066abc1c809c1c807aa86c4aa83c7 }


condition:
	$a0
}