rule Win_Trojan_Replicator_5
{
strings:
	$a0 = { 03b440cd21b8004231d231c9cd215a58813e0a034d5a }


condition:
	$a0
}