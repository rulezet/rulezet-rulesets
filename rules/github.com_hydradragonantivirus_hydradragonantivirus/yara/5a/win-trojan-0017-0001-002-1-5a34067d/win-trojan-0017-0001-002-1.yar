rule Win_Trojan__0017_0001_002_1
{
strings:
	$a0 = { 8bfd83c72d515757e8b3005a8b4e27b440cd21e8c2045a59b440cd21e81902b440cd21b8004233 }


condition:
	$a0
}