rule Win_Trojan_Andromeda_6
{
strings:
	$a0 = { fc4b7503e98dfd80fc30750981feb4a37503bfa3a3fb }


condition:
	$a0
}