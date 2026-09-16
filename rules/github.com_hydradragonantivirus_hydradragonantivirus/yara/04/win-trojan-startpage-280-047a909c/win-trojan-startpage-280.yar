rule Win_Trojan_Startpage_280
{
strings:
	$a0 = { 616466696c65732f78626164612e75726c0000005cbcbac0cebbe7c0ccc6aeb8f0c0bd2e75726c005cbcbac0ceb3eec0ccb8b6b4e7000000687474703a2f2f63616c6c626f }


condition:
	$a0
}