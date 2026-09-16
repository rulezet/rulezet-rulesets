rule Win_Trojan_Uck_1
{
strings:
	$a0 = { be1a01e67429b80001b9db022bc8b4408d960001cd2183c60b8bd633c9b80042cd21b903008d96 }


condition:
	$a0
}