rule Win_Downloader_Small_1336
{
strings:
	$a0 = { 2f78646d706bbbffeffe736f732e6a706734633a5c6d7333322e7379730055242d41fbeddfff67656e743a2025730d0a544d6963 }


condition:
	$a0
}