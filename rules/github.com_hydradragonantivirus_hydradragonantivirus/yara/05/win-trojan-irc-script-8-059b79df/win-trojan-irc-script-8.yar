rule Win_Trojan_IRC_Script_8
{
strings:
	$a0 = { 2f6d736720246e69636b202e626b6c203c6f6e2f6f66662f636c6561723e202d2003313453 }


condition:
	$a0
}