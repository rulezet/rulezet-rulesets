rule Win_Trojan_Tiny_63
{
strings:
	$a0 = { f2ae741eb002e82f0050b440b1efcd21e823008bfab0e9aa5840abb05aaab440cd21b43ecd21 }


condition:
	$a0
}