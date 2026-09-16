rule Win_Trojan_Burglar_10
{
strings:
	$a0 = { de36366db6c93542351b2636665e2036fd8efb9dfb170b8c }


condition:
	$a0
}