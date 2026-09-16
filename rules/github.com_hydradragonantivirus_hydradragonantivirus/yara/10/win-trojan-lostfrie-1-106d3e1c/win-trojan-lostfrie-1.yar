rule Win_Trojan_Lostfrie_1
{
strings:
	$a0 = { 6f048db60c01b986012e31144646e2f9c32e8b166f04be0c01b986012e31144646e2f9c32e }


condition:
	$a0
}