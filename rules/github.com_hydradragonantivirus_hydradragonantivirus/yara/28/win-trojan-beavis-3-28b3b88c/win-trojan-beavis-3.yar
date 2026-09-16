rule Win_Trojan_Beavis_3
{
strings:
	$a0 = { 7cbefe008a0734904e30000bf675f9c344ad00f00072 }


condition:
	$a0
}