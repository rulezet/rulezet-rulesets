rule Win_Downloader_Delf_1095
{
strings:
	$a0 = { 0e8b0b5a16c955bd12cb39bb9344c51d14a0b2ff9e3a6aec03c166a828153a01d2c856b981777a6c31f2a59bb3c2224aa1d127abefe08b92b4757ceac7a2116836a18ff102dc3242dc1ec2c426cc5acd }


condition:
	$a0
}