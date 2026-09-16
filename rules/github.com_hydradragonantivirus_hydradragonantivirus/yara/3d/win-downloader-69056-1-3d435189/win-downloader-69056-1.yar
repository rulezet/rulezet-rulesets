rule Win_Downloader_69056_1
{
strings:
	$a0 = { 446f776e6c6f616446696c65[0-10]4b4a415348444a4b }


condition:
	$a0
}