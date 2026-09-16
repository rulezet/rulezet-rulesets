rule Win_Trojan_Agent_36203
{
strings:
	$a0 = { e800310000e978feffffcccccccccccccccccccccccccccccc8b4c2404f7c10300000074248a0183c10184 }


condition:
	$a0
}