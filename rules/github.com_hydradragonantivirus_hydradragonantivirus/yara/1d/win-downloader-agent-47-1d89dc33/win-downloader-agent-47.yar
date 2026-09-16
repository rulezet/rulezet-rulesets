rule Win_Downloader_Agent_47
{
strings:
	$a0 = { bfaa5028cdb2781265aa596a3312655f9edd14eeddcfcec9c9c9c9c9c966eca9c966cc8d66cc817144676666687474703a2f2f7365617263686d65 }


condition:
	$a0
}