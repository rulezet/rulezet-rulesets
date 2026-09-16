rule Win_Downloader_Small_1964
{
strings:
	$a0 = { 837d0c01754168dc1500106a016a00e85d000000ff75088f0500300010a304300010 }


condition:
	$a0
}