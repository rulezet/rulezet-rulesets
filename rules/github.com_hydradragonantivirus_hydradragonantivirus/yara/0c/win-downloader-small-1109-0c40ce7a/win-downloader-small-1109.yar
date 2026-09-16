rule Win_Downloader_Small_1109
{
strings:
	$a0 = { 620f21631372eebaaeeb1f6f21730f72076c136300697db1ae6b6e096d116e211f66cabd89ec47232e8311f2ee5b6cbe6d726e2e6578650b6d7362635b3c781a }


condition:
	$a0
}