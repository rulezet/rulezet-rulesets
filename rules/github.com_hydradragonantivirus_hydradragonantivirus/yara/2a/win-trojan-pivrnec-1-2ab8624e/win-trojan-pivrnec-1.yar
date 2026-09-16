rule Win_Trojan_Pivrnec_1
{
strings:
	$a0 = { b440b91b038d960001cd213bc17516b8004233c933d2cd21720bb440b907008d966303cd21 }


condition:
	$a0
}