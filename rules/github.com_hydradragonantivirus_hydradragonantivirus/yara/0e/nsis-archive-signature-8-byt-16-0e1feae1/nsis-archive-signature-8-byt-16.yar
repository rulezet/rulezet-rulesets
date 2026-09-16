rule Nsis_archive_signature__8_byt_16_
{
strings:
	$a0 = { efbeadde4e756c6c736f6674496e7374 }

condition:
	$a0
}