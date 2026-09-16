rule Win_Downloader_Banload_1129
{
strings:
	$a0 = { 0c932fc6d4a5ba84ba01ae0d71f8bbe3481aba1950336890a386933fa293e6d6c25ffaf82999de90e7b48b0e08cfb2446689f5e4736623130824c294 }


condition:
	$a0
}