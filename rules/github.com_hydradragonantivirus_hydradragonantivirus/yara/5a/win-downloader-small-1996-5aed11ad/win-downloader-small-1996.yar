rule Win_Downloader_Small_1996
{
strings:
	$a0 = { 8f050030001085c07537508bc4506a006a0068e81500106a006a00e83400000083c404eb1c }


condition:
	$a0
}