rule Win_Downloader_Small_2604
{
strings:
	$a0 = { a31820400033c05050be7810400056685810400050e852010000 }


condition:
	$a0
}