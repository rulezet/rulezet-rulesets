rule Win_Downloader_8325_1
{
strings:
	$a0 = { 2140a734e97340dd75e0414e54497256525207abd1c8fa0746494c4500 }


condition:
	$a0
}