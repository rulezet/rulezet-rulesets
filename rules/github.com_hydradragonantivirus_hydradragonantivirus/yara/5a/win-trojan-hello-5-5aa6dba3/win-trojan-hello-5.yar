rule Win_Trojan_Hello_5
{
strings:
	$a0 = { 57b80100509ad8061f019a91021f01bf42531e57bf72001e57b810275031c050509ac307 }


condition:
	$a0
}