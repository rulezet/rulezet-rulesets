rule Win_Downloader_72955_1
{
strings:
	$a0 = { 6200000075670000726570006f72 }

	$a1 = { 372600007569643d }

	$a2 = { 6f70656e0000000068740000703a2f002f }


condition:
	$a0 and $a1 and $a2
}