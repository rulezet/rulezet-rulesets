rule Win_Trojan_Mybot_8274
{
strings:
	$a0 = { e51b2438d069798fa2a1abd7f6b3b86535c468bfa6966a7236ae741a7614fb6411be703914341154c61b5ea17cecb464d2bb426029b8d4c66b550d357e3f9abfa8f59df7cdd7 }


condition:
	$a0
}