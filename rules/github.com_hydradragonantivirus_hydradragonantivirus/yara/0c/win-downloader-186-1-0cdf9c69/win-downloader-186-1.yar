rule Win_Downloader_186_1
{
strings:
	$a0 = { 70ffffff898518ffffff8b458c018518ffffff80f26d8dbd20ffffff83c70880ca498b07398518ffffff7c02eb21c745b82800000080f23980c25f8b8506feffff0145b88b45b80185d4feffffeb10c785d4feffff }


condition:
	$a0
}