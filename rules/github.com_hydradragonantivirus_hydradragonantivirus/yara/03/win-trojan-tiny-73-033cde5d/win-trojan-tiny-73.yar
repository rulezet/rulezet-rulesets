rule Win_Trojan_Tiny_73
{
strings:
	$a0 = { db00d1e973014e8bfead33c3abe2fa5e595b58c3e8dcff89843c02b4408d940501b93401cd219c }


condition:
	$a0
}