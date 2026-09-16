rule Win_Trojan_RIOTRIO_1435_1
{
strings:
	$a0 = { 8686068dbe0301b9b80231054747e2fac3 }


condition:
	$a0
}