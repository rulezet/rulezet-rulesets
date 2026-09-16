rule Win_Downloader_Banload_1559
{
strings:
	$a0 = { af430aa889e89eba5eb8b7b229af50b90ca13863e44c2eae77e44b5a91beb718db5b2e6eba032373ff1e24ffe701ed580000a84174 }


condition:
	$a0
}