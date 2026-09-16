rule Win_Downloader_Small_3217
{
strings:
	$a0 = { c933739304b7dea41ec6e6ceef7ddc201ccda2abc17306ec62ffa0437adb06e4c17ba74664d7d9ebc1fbbe5d7f99bd44ef51ac3a7d8b833d432c817d6fd12c5941fa846899f1 }


condition:
	$a0
}