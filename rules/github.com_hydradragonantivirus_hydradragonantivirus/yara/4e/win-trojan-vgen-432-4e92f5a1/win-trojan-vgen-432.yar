rule Win_Trojan_VGEN_432
{
strings:
	$a0 = { ba3502cd217245ba9e00b8023dcd21723793b80057cd21515280fe80731fb8024233c933d2cd21be0001bfca02b9 }


condition:
	$a0
}