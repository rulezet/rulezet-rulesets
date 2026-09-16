rule Win_Trojan_Spam_5
{
strings:
	$a0 = { 205559340c436c69656e74486569676874 }


condition:
	$a0
}