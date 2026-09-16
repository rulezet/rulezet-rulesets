rule Win_Trojan_Downloader_31
{
strings:
	$a0 = { 616e626179616e6963682e62792e72752f6c6f616465722e657865 }


condition:
	$a0
}