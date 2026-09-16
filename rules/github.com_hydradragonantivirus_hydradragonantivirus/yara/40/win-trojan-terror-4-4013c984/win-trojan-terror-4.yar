rule Win_Trojan_Terror_4
{
strings:
	$a0 = { b90d00be0e0106bf000157f3a4061fcb }


condition:
	$a0
}