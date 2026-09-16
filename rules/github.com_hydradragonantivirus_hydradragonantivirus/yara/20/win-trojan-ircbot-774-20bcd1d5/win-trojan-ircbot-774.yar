rule Win_Trojan_IRCBot_774
{
strings:
	$a0 = { baea144000b900000000803c0a0a740d803c0a000f848d00000041ebed }


condition:
	$a0
}