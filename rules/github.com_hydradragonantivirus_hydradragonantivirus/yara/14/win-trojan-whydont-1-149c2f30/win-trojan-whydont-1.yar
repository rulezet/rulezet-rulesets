rule Win_Trojan_Whydont_1
{
strings:
	$a0 = { 1f28b91a012e81374d044343e2f7a5044d941094cce95f044b1af54c7dc96c85b64919700f88954cc3dccc2a4e04cd }


condition:
	$a0
}