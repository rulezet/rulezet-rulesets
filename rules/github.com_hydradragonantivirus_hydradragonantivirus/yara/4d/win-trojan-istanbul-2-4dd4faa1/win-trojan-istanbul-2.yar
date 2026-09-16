rule Win_Trojan_Istanbul_2
{
strings:
	$a0 = { a1f1042d03002ea3fd042ec606fb040133d2b96905b440e848fe33c933d2b80042e83efebafc04 }


condition:
	$a0
}