rule Win_Trojan_BugsBunny_2
{
strings:
	$a0 = { a303003dc800723cb440b9f10133d2cd21be0500c704e90046a10300051a008904b8004233c933d2 }


condition:
	$a0
}