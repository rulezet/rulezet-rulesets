rule Win_Trojan_Eternity_1
{
strings:
	$a0 = { e800005d83ed03e81400eb25e80f00b440b932028bd5cd21e80300c3 }


condition:
	$a0
}