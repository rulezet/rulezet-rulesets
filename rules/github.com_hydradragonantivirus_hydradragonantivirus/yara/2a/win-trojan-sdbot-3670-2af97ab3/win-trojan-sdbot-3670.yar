rule Win_Trojan_SdBot_3670
{
strings:
	$a0 = { a4b037197e05875b92d6b6ba4f66cc99837555ce2e8390908fd442ae836c1f9ce8873b38da07b6832efceebdad5bd8b07f14c9c8d91e8c2e1f972a93fedb9620187c0b72d78a07e672f6ff7c28be }


condition:
	$a0
}