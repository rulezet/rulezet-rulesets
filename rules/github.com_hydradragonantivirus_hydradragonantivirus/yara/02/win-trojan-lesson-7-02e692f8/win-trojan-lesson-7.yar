rule Win_Trojan_Lesson_7
{
strings:
	$a0 = { ee08018b842202a300018b842402a302018a842602a20401b41a8d949c01cd21b44e33c98d941c02cd21725ab802 }


condition:
	$a0
}