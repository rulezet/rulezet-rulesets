rule Win_Trojan_Duwende_1
{
strings:
	$a0 = { 86f63551a9a8419ea776a91b4145818082f635744566a9ce4180867e3474ebb54df6eb9e8974ead5697182c6c19e0b76 }


condition:
	$a0
}