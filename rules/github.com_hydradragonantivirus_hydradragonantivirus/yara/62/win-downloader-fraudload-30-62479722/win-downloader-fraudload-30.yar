rule Win_Downloader_FraudLoad_30
{
strings:
	$a0 = { 526567456e756d4b6579457857[1]47444933322e444c4c[4]47657444434f72674578 }


condition:
	$a0
}