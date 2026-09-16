rule Win_Trojan_Hupigon_698
{
strings:
	$a0 = { d10f63febdae69c26b53ff5f73a2a5b8b51e3a433addac0344c4c0e026276fff66d6521bc3dc1043b10585561a1b5ead995bc801f91f511ba99d8150c4d2ebd56d }


condition:
	$a0
}