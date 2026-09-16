rule Win_Downloader_Banload_244
{
strings:
	$a0 = { 26e3f8732fed313d6eac88da7f6cc226b0268f0c2e6e27ab8009ae6abf593ece2b625990728d9a0bdaa88fa7b7852d7f58018e59cae75e98fd18ce8a720742a9acb0d88a9bf335f0a9f4acbfa220 }


condition:
	$a0
}