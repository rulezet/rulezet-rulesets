rule Win_Downloader_Banload_837
{
strings:
	$a0 = { aa3933bfc1a48e4cef21ef33fc4da3c048c7c91b3ed1ab62ac5c53c61f8834c37dc425c0a5df43dfdca0c6770b7e422aba2b28241bd5169cda3a6c249c340720c1cbe6256c8e7cc2 }


condition:
	$a0
}