rule Win_Trojan_Day2_1
{
strings:
	$a0 = { 0e1f0e078b1ebe07bf1a028bf7b9c402ad2bc333c3abe2f857b88dd1238dffaa177928c3 }


condition:
	$a0
}