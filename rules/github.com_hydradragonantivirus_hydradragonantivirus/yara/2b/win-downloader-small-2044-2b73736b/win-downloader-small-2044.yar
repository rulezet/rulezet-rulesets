rule Win_Downloader_Small_2044
{
strings:
	$a0 = { d86874e270383a2fba759864613a2e6dd9343073c966efd78eff0a2f77811b648cfd271cea427cf43a3d }


condition:
	$a0
}