rule Win_Trojan_Spinner_1
{
strings:
	$a0 = { bca41aa25c6f839ef7d7a14b34a2acbd2e62ea2c6284229ca2a2f8d6a14b26a28403a1a28fa2a3d1 }


condition:
	$a0
}