rule Win_Trojan_XRes_3
{
strings:
	$a0 = { b440b9b00133d2cd21b8004233d233c9cd21e8230080ec }


condition:
	$a0
}