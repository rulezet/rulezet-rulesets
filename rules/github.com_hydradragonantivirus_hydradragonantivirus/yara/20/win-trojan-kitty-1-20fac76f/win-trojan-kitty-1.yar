rule Win_Trojan_Kitty_1
{
strings:
	$a0 = { 078ed3bc7a020ee800005e1f83ee4dfcac08c0740f347b1e56b40ebb0700cd105e1febebbb100009db74db4bb9 }


condition:
	$a0
}