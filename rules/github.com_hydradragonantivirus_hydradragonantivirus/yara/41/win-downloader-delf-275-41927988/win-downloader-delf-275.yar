rule Win_Downloader_Delf_275
{
strings:
	$a0 = { 182750466c2cdbbfcc01cbeff7ff0c8a1e4680fb2074f8b5000d2d7462092b745f24762f2f3f78745a5874553075134e22dfdb179f484384f320eb040a2d80eb30230977 }

	$a1 = { ddc2ccc9b3b8b5ada0b5a89ad2aaaccf9da1a37972654b3f6e7064aab6b0 }


condition:
	$a0 and $a1
}