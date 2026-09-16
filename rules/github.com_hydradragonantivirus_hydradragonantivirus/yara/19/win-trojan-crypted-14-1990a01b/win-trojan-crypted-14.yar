rule Win_Trojan_Crypted_14
{
strings:
	$a0 = { eb065652554c5a00909090[0-8]8b042483e84f680b731413ffd0b8001014133d }


condition:
	$a0
}