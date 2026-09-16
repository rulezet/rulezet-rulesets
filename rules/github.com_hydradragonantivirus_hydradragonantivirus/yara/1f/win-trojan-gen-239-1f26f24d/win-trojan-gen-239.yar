rule Win_Trojan_Gen_239
{
strings:
	$a0 = { c07430833e3e01007f0a7c27813e3c01f016761f8dbe00fe1657bf4d011e579afd097700bf4001 }


condition:
	$a0
}