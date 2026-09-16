rule Win_Downloader_Swizzor_299
{
strings:
	$a0 = { 9f0b2f73ab2576828c86a0c2987e46f7ebb23f14dcd94c2d9b9e862ce72e27d09de55a48cf9f67dc8077693e4c27bf3c }


condition:
	$a0
}