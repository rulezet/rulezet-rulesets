rule Win_Trojan_Small_3812
{
strings:
	$a0 = { d1f1580d861b7770ce3bdd86b1aa3b0d6c1c7c15576b0f055a37466ef66ad57f92971fc9bbd30d496cd9fcb05a07d4ce58ce7a68e53bf9232a90c4ff785fd3b23e }


condition:
	$a0
}