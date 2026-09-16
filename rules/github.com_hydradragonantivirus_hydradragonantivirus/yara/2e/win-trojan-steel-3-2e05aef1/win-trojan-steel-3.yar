rule Win_Trojan_Steel_3
{
strings:
	$a0 = { 80fcfe73c6e874ffb8004233c9ba0100cd21b4408d941202b90200cd21b43ecd21b41aba8000 }


condition:
	$a0
}