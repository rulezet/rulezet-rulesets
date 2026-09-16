rule Win_Trojan_Downloader_163
{
strings:
	$a0 = { 6666663d6f702e73706c69742822??????2229[0-30]6666662e6f702e7265706c6163652822??????2229 }


condition:
	$a0
}