rule Win_Trojan_Subsys_20
{
strings:
	$a0 = { af416338a60070a4755b4b254bfbc66d7bdad18bc96a7c11cde10b5b54078315f4cdadfbc3c2e8cef10ca97656f09b08 }


condition:
	$a0
}