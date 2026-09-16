rule Win_Downloader_Delf_977
{
strings:
	$a0 = { 73ba7f8da8aafd051e7a876cb0ca0fbfb2fd02425f76cbd690ea977b8218523d1e95ec1349d5de0462f31db0474f93fa69c0771aac9fafe1193d819668bac8c89cf915e8c523 }


condition:
	$a0
}