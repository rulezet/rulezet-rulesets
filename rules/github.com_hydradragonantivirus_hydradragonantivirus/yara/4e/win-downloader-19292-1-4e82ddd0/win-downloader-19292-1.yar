rule Win_Downloader_19292_1
{
strings:
	$a0 = { 5033c9bac8000000b890074400e8d5f4ffff8b45ece8a546fcff5068610300008d45e85033c9bac8000000b8ac074400e8b2f4ffff8b45e8e88246fcff }


condition:
	$a0
}