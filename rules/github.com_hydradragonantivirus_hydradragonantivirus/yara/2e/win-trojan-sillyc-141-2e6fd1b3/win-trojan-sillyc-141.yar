rule Win_Trojan_SillyC_141
{
strings:
	$a0 = { 80fcfe73bfe86dffb8004233c9ba0100cd21b4408d940902b90200cd21b80157595acd21b43e }


condition:
	$a0
}