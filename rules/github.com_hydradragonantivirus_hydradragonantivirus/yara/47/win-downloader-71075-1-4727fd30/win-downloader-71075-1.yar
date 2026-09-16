rule Win_Downloader_71075_1
{
strings:
	$a0 = { 5452554500000000558bec83c4ec53565733c08945ecb864834200e878d5fdff }

	$a1 = { 536f7542656c6f454c696e64616f }


condition:
	$a0 and $a1
}