rule Win_Trojan_Horse_5
{
strings:
	$a0 = { 0e07b90800f3a4b02eaab90300f3a4 }


condition:
	$a0
}