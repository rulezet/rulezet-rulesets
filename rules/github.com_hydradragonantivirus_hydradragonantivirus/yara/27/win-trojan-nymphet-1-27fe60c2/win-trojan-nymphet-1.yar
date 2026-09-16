rule Win_Trojan_Nymphet_1
{
strings:
	$a0 = { a901c744160000b800408b1edb01babb01b91c005058cd21b801578b1edb01b900168b161800 }


condition:
	$a0
}