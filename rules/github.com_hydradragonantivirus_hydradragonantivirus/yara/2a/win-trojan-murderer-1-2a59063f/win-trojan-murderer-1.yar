rule Win_Trojan_Murderer_1
{
strings:
	$a0 = { 213d03077508e99600ba560fcd27e83ffab42acd2181fa0307750c2ec606f405012ec606f70530 }


condition:
	$a0
}