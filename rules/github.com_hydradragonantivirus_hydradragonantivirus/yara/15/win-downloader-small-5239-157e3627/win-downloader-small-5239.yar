rule Win_Downloader_Small_5239
{
strings:
	$a0 = { 087e216bbf6c706163f7bf3bf77d8b737669049b6c673d5f6874dbb6dbff74703a2f2f7a7863767aa76f }


condition:
	$a0
}