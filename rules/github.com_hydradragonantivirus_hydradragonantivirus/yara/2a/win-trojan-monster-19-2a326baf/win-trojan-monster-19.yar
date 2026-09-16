rule Win_Trojan_Monster_19
{
strings:
	$a0 = { e2fba24a4a14c9a449a2884b876a8c0e5bb4a14a8c0e5b4aa2c64bc1ce7a48e94a4bc0ce7848e8484bf2 }


condition:
	$a0
}