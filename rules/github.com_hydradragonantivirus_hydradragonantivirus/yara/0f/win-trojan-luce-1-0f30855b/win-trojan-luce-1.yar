rule Win_Trojan_Luce_1
{
strings:
	$a0 = { d21eba3f05ce348542bb405409d30c0d92610bb6e750d6cb }


condition:
	$a0
}