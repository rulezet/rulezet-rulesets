rule Win_Downloader_Small_3406
{
strings:
	$a0 = { d3ef9e9fd2c94c07167d78ce94d5ad24de6365df05b6324bf14600fdf3a902c612c66b0c2703674d504a9d621738c2dd89dd0718b293a495e86ceb8789d74394 }


condition:
	$a0
}