rule Win_Downloader_Agent_31896
{
strings:
	$a0 = { 383f242e26267978642f322f6a6f396626252b2e4a327a }


condition:
	$a0
}