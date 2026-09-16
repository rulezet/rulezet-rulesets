rule Win_Trojan_Zyrtec_1
{
strings:
	$a0 = { e8000054584040507501055c5e83ee188bfe060e1f2b74fe2b74fe2bfe2ec6446700893cb4 }


condition:
	$a0
}