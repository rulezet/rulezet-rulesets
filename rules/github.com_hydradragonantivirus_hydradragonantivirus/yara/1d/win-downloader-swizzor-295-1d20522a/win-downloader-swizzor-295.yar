rule Win_Downloader_Swizzor_295
{
strings:
	$a0 = { 7c7390f6911a2590d2941bffc6c279a9ce4ea9dd3b841e52f0c4c3583d5882e017b29ab8dd26d3ac6ae1c9896dd7b9f1 }


condition:
	$a0
}