rule Win_Trojan_Vgen_123
{
strings:
	$a0 = { e800005d81ed03018db68c01bf0001a5a58d969001b41acd218d968201b44ecd2172538d96ae01b8023dcd21724493b9 }


condition:
	$a0
}