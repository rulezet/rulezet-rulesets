rule Win_Trojan_Skism_4
{
strings:
	$a0 = { 018b1ee50153e8e0ff5bb92803b440cd2153e8 }


condition:
	$a0
}