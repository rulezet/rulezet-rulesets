rule Win_Trojan_Small_5338
{
strings:
	$a0 = { 6c1c7c15576b0f055a37466ef66ad57f92971fc9bbd30d496cd9fcb05a07d4ce58ce7a68e53bf9232a90c4ff785fd3b23e5b95636ce7d9ba572fc9fbf11623042a }


condition:
	$a0
}