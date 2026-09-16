rule Win_Trojan_Dark_1
{
strings:
	$a0 = { 4d74073d4d5a7402eb388b9e2005b9f8038bd5b440cd2133c933d2b80242cd21b90002f7f183 }


condition:
	$a0
}