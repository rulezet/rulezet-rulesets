rule Win_Trojan_Agent_36851
{
strings:
	$a0 = { b3acac32c33428aafec3e2f633c08a859b000000 }


condition:
	$a0
}