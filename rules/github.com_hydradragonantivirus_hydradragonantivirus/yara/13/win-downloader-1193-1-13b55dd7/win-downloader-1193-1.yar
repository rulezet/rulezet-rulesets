rule Win_Downloader_1193_1
{
strings:
	$a0 = { 558bec81ecac04000053566897deec6733db6a01899d08ffffffe884f8ffff535353538d8d08ffffff5153536820414000ffd0ffb508ffffff8d85e4feffff681c41400050ff1528304000 }


condition:
	$a0
}