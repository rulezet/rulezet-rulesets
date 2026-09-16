rule Win_Trojan_DDoS_6
{
strings:
	$a0 = { 5c4b6579626f617264204c61796f7574735c252e3878 }

	$a1 = { 73656e64 }

	$a2 = { 52756e }

	$a3 = { 5d2d5b57585d2d5b }


condition:
	$a0 and $a1 and $a2 and $a3
}