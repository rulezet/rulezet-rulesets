rule Win_Trojan_Mwin_1
{
strings:
	$a0 = { 568bfeb9fe0190ac32c4aad0c4fec432e1e2f4c350e8e4ff00b8dbc8cddb5ffe349d194dda113782a1c6eb812f7711e7b34c204c0aaf83238118779c71199e3009 }


condition:
	$a0
}