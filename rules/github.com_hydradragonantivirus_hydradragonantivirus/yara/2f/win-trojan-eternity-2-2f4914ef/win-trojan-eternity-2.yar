rule Win_Trojan_Eternity_2
{
strings:
	$a0 = { e80000e806005d83ed03eb08b8050333dbcd16c3e81400eb25e80f00b440b99b018bd5cd21e80300 }


condition:
	$a0
}