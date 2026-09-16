rule Win_Trojan_F_7
{
strings:
	$a0 = { 50b80d001e1f530bdb5b50eb0358eb3fe822002e803e3a030775f5c3 }


condition:
	$a0
}