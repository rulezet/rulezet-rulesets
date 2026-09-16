rule Win_Downloader_Small_1305
{
strings:
	$a0 = { 78ab241b7702ff8fc0726c696e6bf062ea7a062f736f66745454 }


condition:
	$a0
}