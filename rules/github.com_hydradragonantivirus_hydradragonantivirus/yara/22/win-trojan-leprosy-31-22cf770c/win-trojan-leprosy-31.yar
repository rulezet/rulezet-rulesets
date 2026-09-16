rule Win_Trojan_Leprosy_31
{
strings:
	$a0 = { 908a273226060188274381fbcf037ef090c3 }


condition:
	$a0
}