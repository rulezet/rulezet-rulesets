rule Win_Downloader_Small_2005
{
strings:
	$a0 = { a3a40f4500ff35740f4500ff15a40f45006a0168f40e4500e895000000 }


condition:
	$a0
}