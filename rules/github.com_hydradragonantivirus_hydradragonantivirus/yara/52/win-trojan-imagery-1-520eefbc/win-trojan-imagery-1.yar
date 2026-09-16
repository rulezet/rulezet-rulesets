rule Win_Trojan_Imagery_1
{
strings:
	$a0 = { 9a00003d019a0d00b2005589e5b800029acd023d0181ec0002e897f7bf6e031e57bf800a0e5731c0509a70063d018dbe }


condition:
	$a0
}