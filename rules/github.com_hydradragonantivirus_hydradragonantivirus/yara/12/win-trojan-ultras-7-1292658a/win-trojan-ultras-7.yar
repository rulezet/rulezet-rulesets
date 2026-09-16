rule Win_Trojan_Ultras_7
{
strings:
	$a0 = { 2e7368656c6c22292e72756e2822633a5c5c756c747261732e6578652229 }


condition:
	$a0
}