rule Win_Trojan_Agent_34195
{
strings:
	$a0 = { 9c60e8000000005d83ed074083f87f75fabb0000400003d8eb02 }


condition:
	$a0
}