rule Win_Trojan_Loz_3
{
strings:
	$a0 = { 5053515257061ee800005e2e8a44f52c0074118bfe83c71a90b9ee0a2e3005fec047e2f8 }


condition:
	$a0
}