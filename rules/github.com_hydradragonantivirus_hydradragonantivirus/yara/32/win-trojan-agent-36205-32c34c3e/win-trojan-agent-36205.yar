rule Win_Trojan_Agent_36205
{
strings:
	$a0 = { 60720886d6 }


condition:
	$a0
}