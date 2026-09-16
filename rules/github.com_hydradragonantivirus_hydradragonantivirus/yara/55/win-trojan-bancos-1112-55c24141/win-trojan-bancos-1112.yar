rule Win_Trojan_Bancos_1112
{
strings:
	$a0 = { ba00d3e997c25504c454e486521ff66786edec0e2311f0055d75ffe26a32aaa2b700d96ec4e358e2f73205ceac04e4c38b17eec6cd5b4c01942da8dcf389f5d90ff9f3b5de9c3f5dd075ebbf4dba6392389b }


condition:
	$a0
}