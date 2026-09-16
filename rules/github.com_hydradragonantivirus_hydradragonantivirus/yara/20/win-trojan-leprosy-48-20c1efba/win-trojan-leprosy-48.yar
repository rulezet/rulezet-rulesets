rule Win_Trojan_Leprosy_48
{
strings:
	$a0 = { 0100c3bb30018a2f322e0601882f4381fbe2047ef1c3 }


condition:
	$a0
}