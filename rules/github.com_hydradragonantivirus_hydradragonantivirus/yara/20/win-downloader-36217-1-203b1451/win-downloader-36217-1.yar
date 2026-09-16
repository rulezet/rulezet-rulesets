rule Win_Downloader_36217_1
{
strings:
	$a0 = { b9e8314500ba003245008b45fce813ffffff84c0740c6a006824324500e8d331fbff }


condition:
	$a0
}