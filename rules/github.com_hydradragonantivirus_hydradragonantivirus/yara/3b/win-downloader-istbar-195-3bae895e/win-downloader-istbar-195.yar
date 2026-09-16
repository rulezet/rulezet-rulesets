rule Win_Downloader_Istbar_195
{
strings:
	$a0 = { 4a7955444d6f000000006354346e52656c68 }


condition:
	$a0
}