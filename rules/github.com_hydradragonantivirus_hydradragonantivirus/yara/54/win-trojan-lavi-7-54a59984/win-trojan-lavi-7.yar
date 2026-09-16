rule Win_Trojan_LAVI_7
{
strings:
	$a0 = { b9fe0381e91601268a02344626880246e2f5c3 }


condition:
	$a0
}