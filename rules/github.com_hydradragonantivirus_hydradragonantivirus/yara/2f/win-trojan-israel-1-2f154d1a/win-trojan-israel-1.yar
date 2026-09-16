rule Win_Trojan_Israel_1
{
strings:
	$a0 = { 3e0c004452741f26803fea750b26817f05fb807503eb0f90b43080c44090b0f086e0cd2107c3 }


condition:
	$a0
}