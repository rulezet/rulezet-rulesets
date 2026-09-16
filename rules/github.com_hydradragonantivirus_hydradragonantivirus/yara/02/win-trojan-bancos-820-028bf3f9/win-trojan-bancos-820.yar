rule Win_Trojan_Bancos_820
{
strings:
	$a0 = { 3dff92bfd44a1666c57cd4769c961bf63462b58e3fe3998b9b1f15a535fe88e866baaaeb715dcee8a5c42f5f45522afbb0d584903a5e8996baef475946dfda09ca3791d309db }


condition:
	$a0
}