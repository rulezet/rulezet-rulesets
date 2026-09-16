rule Win_Downloader_Small_5140
{
strings:
	$a0 = { 0fb7c6413bc872d484db0fb6cb8d8113204000761abe13204000ba08214000 }


condition:
	$a0
}