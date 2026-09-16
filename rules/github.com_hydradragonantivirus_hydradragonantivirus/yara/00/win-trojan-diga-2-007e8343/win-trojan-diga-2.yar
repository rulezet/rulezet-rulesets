rule Win_Trojan_Diga_2
{
strings:
	$a0 = { bae101e84700721fb8023dba9e00e83c0093b4408a0eff00ba0001e82f00b43ee82a00b44febdcb4 }


condition:
	$a0
}