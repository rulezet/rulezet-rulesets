rule Win_Trojan_IRC_9
{
strings:
	$a0 = { cce9ffffffffffff5b0000005b4b2d4964656e742076322e30206279204b616973657220536f7a61795d2d5b7777772e }


condition:
	$a0
}