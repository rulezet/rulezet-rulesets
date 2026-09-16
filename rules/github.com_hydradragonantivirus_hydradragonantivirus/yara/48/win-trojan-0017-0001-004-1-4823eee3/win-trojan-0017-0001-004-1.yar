rule Win_Trojan__0017_0001_004_1
{
strings:
	$a0 = { 40cd21e8c2045a59b440cd21e81902b440cd21b8004233c999cd218bd6b90300b440cd218b4c19 }


condition:
	$a0
}