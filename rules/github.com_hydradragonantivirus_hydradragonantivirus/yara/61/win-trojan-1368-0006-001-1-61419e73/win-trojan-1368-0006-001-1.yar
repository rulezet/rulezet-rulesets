rule Win_Trojan__1368_0006_001_1
{
strings:
	$a0 = { b80042e8d9ffb4408d96d801b90400cd21e80e00b41aba8000cd2158bb00010e53cb5e5a59 }


condition:
	$a0
}