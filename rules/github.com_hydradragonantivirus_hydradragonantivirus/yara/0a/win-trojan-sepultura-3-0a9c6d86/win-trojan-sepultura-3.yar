rule Win_Trojan_Sepultura_3
{
strings:
	$a0 = { cd217262930e1fb90500ba2a03b43fcd21a12a0302c43ca7743de851003d74f477352d0500 }


condition:
	$a0
}