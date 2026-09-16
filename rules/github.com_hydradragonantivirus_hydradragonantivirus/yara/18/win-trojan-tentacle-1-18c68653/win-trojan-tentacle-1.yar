rule Win_Trojan_Tentacle_1
{
strings:
	$a0 = { 59b800428b5e51cd217303e99800b440b99807ba0000cd217303e98900b440b90a00ba2900cd21 }


condition:
	$a0
}