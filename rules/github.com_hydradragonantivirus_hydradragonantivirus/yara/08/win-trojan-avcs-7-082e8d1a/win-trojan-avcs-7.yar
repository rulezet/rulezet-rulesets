rule Win_Trojan_AVCS_7
{
strings:
	$a0 = { e800005b81eb11018beb8db63201568b962102b974008bfe3af0fcad33c2ab3ae7e2f8c32adca43daa57e8ea31aaa6d9119810264783b593 }


condition:
	$a0
}