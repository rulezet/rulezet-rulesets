rule Win_Trojan_Angry_1
{
strings:
	$a0 = { 01b440cd2181c70001893e8a01c6068e01deb8004233c933d2cd21b90600ba8901b440cd21b4 }


condition:
	$a0
}