rule Win_Downloader_20048_1
{
strings:
	$a0 = { baf4ce44008b45fce8d4feffff3c0175296a006a006804cf44006808cf44006a008bc3e8f55afeff50e88f77fdff }


condition:
	$a0
}