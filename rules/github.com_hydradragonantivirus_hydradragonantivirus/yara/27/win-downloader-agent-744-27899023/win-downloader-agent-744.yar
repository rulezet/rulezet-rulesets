rule Win_Downloader_Agent_744
{
strings:
	$a0 = { 2e657865000000006965642e657865006a666560743830646000000020000000ffffffffffffffff5175 }


condition:
	$a0
}