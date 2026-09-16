rule Win_Downloader_Banload_1077
{
strings:
	$a0 = { 233a8cf4e186f196b673f61efe3b5784321ffed51543aa82041e4a50bb13ab2e8dd2010a8603af8bd680dba93d0e1b2fee2d94b3da4557 }


condition:
	$a0
}