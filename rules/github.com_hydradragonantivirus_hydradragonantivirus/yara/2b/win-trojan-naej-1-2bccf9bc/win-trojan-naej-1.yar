rule Win_Trojan_Naej_1
{
strings:
	$a0 = { b8023dcc938d96????b91c00b43fcc8bf2ad02e080f4??c38d96????b80143ccc3b44233c999ccc3 }


condition:
	$a0
}