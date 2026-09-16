rule Win_Trojan_Substitution_1
{
strings:
	$a0 = { e800008bec8b6e0083c40281ed07018d9e2801b967018db628028bfeacd7aae2fbe90001 }


condition:
	$a0
}