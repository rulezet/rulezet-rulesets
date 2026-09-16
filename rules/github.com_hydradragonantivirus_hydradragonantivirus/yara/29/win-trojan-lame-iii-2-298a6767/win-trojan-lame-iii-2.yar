rule Win_Trojan_Lame_III_2
{
strings:
	$a0 = { e800005d81ed0300c6867100bec78672007501c6867400c3e85600c6867100bfc7867200 }


condition:
	$a0
}