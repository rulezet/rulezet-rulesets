rule Win_Trojan_Trojan_183
{
strings:
	$a0 = { cd215e8efe81c72d0232c0b94000f2ae4fc7055c00b9 }


condition:
	$a0
}