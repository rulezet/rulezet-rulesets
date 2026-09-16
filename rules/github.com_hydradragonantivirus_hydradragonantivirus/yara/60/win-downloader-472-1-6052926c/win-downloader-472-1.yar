rule Win_Downloader_472_1
{
strings:
	$a0 = { 4aff3fbf4d357779776a8bbd1e958c48141b2e926c9b7e8d41e8ddf4a1b90fb40a618460f9a48d1c6187a19ecc8bd0f753ab2475fa3f7c26bd02b616fba8eb0be512a84f45b3999a24f259dcb289 }


condition:
	$a0
}