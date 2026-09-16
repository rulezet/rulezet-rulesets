rule Win_Trojan_Eternity_5
{
strings:
	$a0 = { 01faba4559cd16e800005d83ed0ce81400eb25e80f00b440b958028bd5cd21e80300c3 }


condition:
	$a0
}