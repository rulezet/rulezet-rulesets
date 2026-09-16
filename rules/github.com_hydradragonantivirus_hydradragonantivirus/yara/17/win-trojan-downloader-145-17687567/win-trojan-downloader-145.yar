rule Win_Trojan_Downloader_145
{
strings:
	$a0 = { 286a2d31343d3d6929206576616c28642b622b632b7a2b66372b67293b7d }


condition:
	$a0
}