rule Win_Trojan_SmallComp_4
{
strings:
	$a0 = { fc4b753e60061e52bf6001578bf20e07acaa0ac075fab4 }


condition:
	$a0
}