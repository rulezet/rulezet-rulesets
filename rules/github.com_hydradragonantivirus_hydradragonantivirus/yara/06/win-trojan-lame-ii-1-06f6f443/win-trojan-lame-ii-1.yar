rule Win_Trojan_Lame_II_1
{
strings:
	$a0 = { 51508d9eb504b93b003e8b862b0531074343e2fa58595bc3 }


condition:
	$a0
}