rule Win_Trojan_IRC_Script_31
{
strings:
	$a0 = { 6f6e20313a73746172743a7b0d0a20202e72756e20[0-8]2e657865202f68696465206d495243 }


condition:
	$a0
}