rule Win_Trojan_Vgen_35
{
strings:
	$a0 = { f68bfe4731dbb348fec731d24ab4068ad6cd21741e3a4702741938f074118ad0cd21463a1774e83a1174e431f6ebe0 }


condition:
	$a0
}