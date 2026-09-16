rule Win_Trojan_Tiny_31
{
strings:
	$a0 = { f3a4b84402669866268706840066ab1e07c3b8004050cd2158b4429933c9cd21b103be03028b }


condition:
	$a0
}