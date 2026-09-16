rule Win_Trojan_Leprosy_57
{
strings:
	$a0 = { 51bb??018a2f322e0301882f4381fb73047ef159c3 }


condition:
	$a0
}