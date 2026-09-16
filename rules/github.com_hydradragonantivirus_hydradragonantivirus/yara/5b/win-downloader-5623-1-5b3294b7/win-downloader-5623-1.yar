rule Win_Downloader_5623_1
{
strings:
	$a0 = { f9e80000000083042405c333c5e800000000c704244f7f4000c3000056b86e6e }


condition:
	$a0
}