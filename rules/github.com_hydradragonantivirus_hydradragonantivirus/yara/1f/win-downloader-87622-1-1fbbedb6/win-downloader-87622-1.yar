rule Win_Downloader_87622_1
{
strings:
	$a0 = { 558bec68131e0000576a8156680c1b243a538dbb857de5a857e826000000597d }


condition:
	$a0
}