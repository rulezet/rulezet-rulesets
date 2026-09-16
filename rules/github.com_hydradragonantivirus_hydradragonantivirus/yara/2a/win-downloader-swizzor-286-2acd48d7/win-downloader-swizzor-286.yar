rule Win_Downloader_Swizzor_286
{
strings:
	$a0 = { 9a89ccba3b342409932f965cc1fbbbb8a45ab57a717106fee2a28e34465e4d76d974f52be922c1c0ccc939d2dba3caaa }


condition:
	$a0
}