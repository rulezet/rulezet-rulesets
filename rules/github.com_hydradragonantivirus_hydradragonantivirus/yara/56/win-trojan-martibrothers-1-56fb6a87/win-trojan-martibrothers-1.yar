rule Win_Trojan_MartiBrothers_1
{
strings:
	$a0 = { 13ba0000b93229bb007eb80902cd13c3 }


condition:
	$a0
}