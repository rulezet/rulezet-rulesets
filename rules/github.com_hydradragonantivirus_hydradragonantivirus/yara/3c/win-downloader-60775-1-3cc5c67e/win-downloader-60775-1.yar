rule Win_Downloader_60775_1
{
strings:
	$a0 = { 55e9992000008b45085068377a4000ff356cd14000c3e9f8f8ffff8b4d0c518b55085268943140 }


condition:
	$a0
}