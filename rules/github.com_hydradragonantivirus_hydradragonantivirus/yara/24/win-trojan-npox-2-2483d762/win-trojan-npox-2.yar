rule Win_Trojan_Npox_2
{
strings:
	$a0 = { c883e9032e890eae02e82c00720ab440baad02b90300cd212e8b0ea9022e8b16ab02b80157cd21 }


condition:
	$a0
}