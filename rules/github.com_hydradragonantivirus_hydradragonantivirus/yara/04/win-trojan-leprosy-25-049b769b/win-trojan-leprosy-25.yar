rule Win_Trojan_Leprosy_25
{
strings:
	$a0 = { 8a273226060188274381fbcb037ef1c3 }


condition:
	$a0
}