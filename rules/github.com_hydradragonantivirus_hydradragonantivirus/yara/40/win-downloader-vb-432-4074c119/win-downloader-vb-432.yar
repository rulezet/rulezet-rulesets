rule Win_Downloader_VB_432
{
strings:
	$a0 = { 7373325599833b5db642bdf8cf1cefc340e70cf3f9e2b023a02d61de5c52ac66dc2a17ae928b75063c8fb749bdbe65cd41c7beb25c9a1cd31a53bcade4230b40 }


condition:
	$a0
}