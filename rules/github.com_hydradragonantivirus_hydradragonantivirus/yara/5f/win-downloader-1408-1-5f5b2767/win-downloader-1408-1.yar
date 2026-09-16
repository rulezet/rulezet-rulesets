rule Win_Downloader_1408_1
{
strings:
	$a0 = { ac83f848a9ac0300171616da135b89b8835ba55b5b265c6c5da9ac836c5da9ac83804fa9ac83705da9ac8d5b83c348a9ac164c6853a9ac16aca357a9aca21b8c }


condition:
	$a0
}