rule Win_Downloader_Small_2130
{
strings:
	$a0 = { 60be156050008dbeebafffff5783cdffeb109090909090908a064688074701db7507 }


condition:
	$a0
}