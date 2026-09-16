rule Win_Trojan_Ratboy_3
{
strings:
	$a0 = { b440b9cf018d960401cd21e80100c38b8621018db64701b9c60031044646e2fac3 }


condition:
	$a0
}