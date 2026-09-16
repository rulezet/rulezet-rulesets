rule Win_Downloader_Swizzor_482
{
strings:
	$a0 = { bd1c32d245b259ee9a3793dd4c138a5a214332e3dc6f737f15021d3953f4bc27d86a86c8b679d2d3f6911ea36bb36a3db711b1d972da3a3e86f58b7dcd076e437c6e8cf7ad7014dc4f436eca7da3 }


condition:
	$a0
}