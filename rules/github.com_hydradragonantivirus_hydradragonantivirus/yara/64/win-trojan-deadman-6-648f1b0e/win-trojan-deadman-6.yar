rule Win_Trojan_Deadman_6
{
strings:
	$a0 = { 0e91ababafabab07b440b90010b2c0cd21b43ecd21b44feb93b409ba8200cd21b8014ccd21 }


condition:
	$a0
}