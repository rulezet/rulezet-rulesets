rule Win_Trojan_Egg_1
{
strings:
	$a0 = { cd6c3c58746ebbffffb44acd21b44a83eb48cd21b448bb4700cd217257488ed8c60600005ac70601000000c606 }


condition:
	$a0
}