rule RealAudio_ATRC_huffcode6__8_byt_31_
{
strings:
	$a0 = { 0002030405060708091415161718193435363738393a3b78797a7b7c7d7e7f }

condition:
	$a0
}