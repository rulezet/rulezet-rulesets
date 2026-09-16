rule Win_Downloader_Keenval_13
{
strings:
	$a0 = { 8bf868000400008d8500fcffff6a0050e8280d00006880374000 }


condition:
	$a0
}