rule Win_Trojan_Tester_1
{
strings:
	$a0 = { 094830043d9f9ce6f3eb9a52e79f9c20b4bab252ce56091d }


condition:
	$a0
}