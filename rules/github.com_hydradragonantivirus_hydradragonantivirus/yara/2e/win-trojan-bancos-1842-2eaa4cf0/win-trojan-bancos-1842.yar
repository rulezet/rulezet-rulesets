rule Win_Trojan_Bancos_1842
{
strings:
	$a0 = { 91b0aae99a56e6a4029e6becdc38ba697316cc871ae4485340fe2b675f9c8b3e6a25d354fdd9fce4486facde3f955f336e388c518fa76fc60da0300e56256cdb2e4346697e2e }


condition:
	$a0
}