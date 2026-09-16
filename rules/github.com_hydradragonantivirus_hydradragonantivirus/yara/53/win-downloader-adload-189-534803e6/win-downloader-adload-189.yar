rule Win_Downloader_Adload_189
{
strings:
	$a0 = { 6801a04b00e801000000c3c36c50f3f09616dc584c78aa66ac56eadb7082d9f0 }


condition:
	$a0
}