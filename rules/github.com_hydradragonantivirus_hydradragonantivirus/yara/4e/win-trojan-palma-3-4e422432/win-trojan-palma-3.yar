rule Win_Trojan_Palma_3
{
strings:
	$a0 = { 8bd581c20401b94f02cd213ec6862f0301908f45028f }


condition:
	$a0
}