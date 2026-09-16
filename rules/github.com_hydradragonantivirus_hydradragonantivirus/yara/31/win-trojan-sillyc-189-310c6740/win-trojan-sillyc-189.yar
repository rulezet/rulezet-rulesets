rule Win_Trojan_SillyC_189
{
strings:
	$a0 = { c2a801b90500b440cd308bd6b97701b440cd308b84ca01050501a30101b8004233c933d2cd30b4 }


condition:
	$a0
}