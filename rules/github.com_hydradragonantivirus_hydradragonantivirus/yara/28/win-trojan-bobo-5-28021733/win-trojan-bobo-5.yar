rule Win_Trojan_Bobo_5
{
strings:
	$a0 = { e800005d83ed3ebf0001be290001eea4a4a4b8bb4bcd213d4bbb74dab82135cd212e899eb5002e8c86b700b81c35 }


condition:
	$a0
}