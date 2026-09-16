rule Win_Trojan_Deviant_3
{
strings:
	$a0 = { b4408d960701b90e02cd21e846ffb801573e8b8e97 }


condition:
	$a0
}