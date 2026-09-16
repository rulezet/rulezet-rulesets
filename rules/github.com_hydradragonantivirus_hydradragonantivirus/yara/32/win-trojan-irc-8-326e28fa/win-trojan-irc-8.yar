rule Win_Trojan_IRC_8
{
strings:
	$a0 = { fa9b8f065e3ca35b5b4b2d4964656efdffffb7ac76322e30206279204b616973657220536f7a61795d2d5b77cfcc1fbb }


condition:
	$a0
}