rule Win_Trojan_Voodo_1
{
strings:
	$a0 = { 84261e24fe248a4231c01a170e1a9a740b6dd20518b80136a28b440ebf7001 }


condition:
	$a0
}