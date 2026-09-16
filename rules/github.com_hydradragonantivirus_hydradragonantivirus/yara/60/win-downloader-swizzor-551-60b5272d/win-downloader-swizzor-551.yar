rule Win_Downloader_Swizzor_551
{
strings:
	$a0 = { b98671df25b19d838c58e49bca60f7cf30644db77a1c528ffdb28d8923a8be6e6273869b3e26c56997bc5217d5528a32fb459e58fdc316030982daf2b7cc303fd6a7567aab1980e2aba09707 }


condition:
	$a0
}