rule Win_Downloader_Small_1976
{
strings:
	$a0 = { 46763868748e703a2f3e83796d616e1c3c632e9e6f7f3e693a673e75ef6c3b80 }


condition:
	$a0
}