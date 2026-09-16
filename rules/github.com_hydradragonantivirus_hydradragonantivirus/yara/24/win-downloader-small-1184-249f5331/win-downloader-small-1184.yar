rule Win_Downloader_Small_1184
{
strings:
	$a0 = { 6e6c6f61642e656e6572677966811802be6f722e636f6d081a65725f021503d32e61 }


condition:
	$a0
}