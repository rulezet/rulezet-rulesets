rule Win_Downloader_Delf_1149
{
strings:
	$a0 = { 9c9a04fd72ab8babffccaf4d34bb4c62420dabb53693fe183ea265c30baa83178b307fcb636a0cdeaa73fe1ed3ca6cbb7c9537044d2e439fc1c3bdf279309fd21c6faf85b2ae797b3e2cd7602294856952 }


condition:
	$a0
}