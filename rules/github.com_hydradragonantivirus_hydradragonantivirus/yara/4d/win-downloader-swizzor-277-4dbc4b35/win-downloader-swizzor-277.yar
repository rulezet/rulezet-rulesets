rule Win_Downloader_Swizzor_277
{
strings:
	$a0 = { df5d77ec1bfed7eee3c45e1791ff06bdf896e5f42f7c195061ff11b7e4b43687aadba60813fd1789dd61107d5f15e056 }


condition:
	$a0
}