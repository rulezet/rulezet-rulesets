rule Win_Downloader_Small_2459
{
strings:
	$a0 = { 6800040000681c57400068e03a4000e8a9faffff681c57400056e82efbffff85c074766a00681c57400056e865faffff }


condition:
	$a0
}