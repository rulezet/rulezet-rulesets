rule Win_Downloader_Delf_136
{
strings:
	$a0 = { ffffffff0c00000044726f703d57696e4469722000000000ffffffff2800000041667465723d }

	$a1 = { 5bc3004d79204167656e742076 }


condition:
	$a0 and $a1
}