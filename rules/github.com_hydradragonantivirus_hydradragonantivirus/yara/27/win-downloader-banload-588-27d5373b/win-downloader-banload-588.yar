rule Win_Downloader_Banload_588
{
strings:
	$a0 = { de18cffe6c41b4e77bb2d2fb7fea018096392aeac587d993dc6d2c5167c514f629a7b8aff48f9b6fb0023c28701d30e99207cbf54dd5ba18559aaf273ec443db2601a2a0 }


condition:
	$a0
}