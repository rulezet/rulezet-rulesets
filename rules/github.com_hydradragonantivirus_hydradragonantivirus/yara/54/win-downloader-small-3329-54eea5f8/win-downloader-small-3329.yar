rule Win_Downloader_Small_3329
{
strings:
	$a0 = { 78530d6674776122c144ea56b3f97a593a7dee3c559c6c41147112e61e1f7a6168fdfa383a2fd182ebce08076d2e62697ad7645fea729e }


condition:
	$a0
}