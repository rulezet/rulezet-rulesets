rule Win_Trojan_Trivial_432
{
strings:
	$a0 = { 2700ba5201cd21720be80b007504b44febf3cd20faebfe }


condition:
	$a0
}