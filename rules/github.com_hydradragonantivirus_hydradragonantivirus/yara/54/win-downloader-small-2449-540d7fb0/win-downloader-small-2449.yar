rule Win_Downloader_Small_2449
{
strings:
	$a0 = { 558bec81eca80400005356576a0559be641014138d7dd88d45d8f3a5508d8558ffffff33db50895dfc66a5ff1524101413 }


condition:
	$a0
}