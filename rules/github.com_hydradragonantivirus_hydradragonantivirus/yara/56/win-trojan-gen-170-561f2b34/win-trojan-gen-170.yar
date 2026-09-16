rule Win_Trojan_Gen_170
{
strings:
	$a0 = { ec009a00008a005589e5c606680a00c60668090031c0a3780da37a0d31c0a37c0da37e0db00050bf740c1e57b8 }


condition:
	$a0
}