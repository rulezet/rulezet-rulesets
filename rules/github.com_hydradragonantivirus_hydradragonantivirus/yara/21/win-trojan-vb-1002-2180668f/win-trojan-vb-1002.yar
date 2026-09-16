rule Win_Trojan_VB_1002
{
strings:
	$a0 = { 68c43a4000e8eeffffff00000000000030000000380000000000000009d880 }

	$a1 = { 4552524f52 }

	$a2 = { 4200610063006b00750070002e }


condition:
	$a0 and $a1 and $a2
}