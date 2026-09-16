rule Win_Downloader_Swizzor_307
{
strings:
	$a0 = { 933c78ce35334ea6b84fce93f8bbd1a3cbb31b31f7db2e620b718f0ffe5ece092b11ee788cfd6d764c2f991bf7e1b3aa }


condition:
	$a0
}