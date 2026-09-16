rule Win_Trojan_Bancos_1040
{
strings:
	$a0 = { af7e5597546969de10d5c0e43e11c955694b98fceeb364a24047fbea7997cb78f7f8606cbb9c85968f119d4b8b03c77e8c5e3e3316d6ef37d7a98df90cf9a1be }


condition:
	$a0
}