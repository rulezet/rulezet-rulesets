rule Win_Downloader_Swizzor_555
{
strings:
	$a0 = { 75eefa4f97be055d12f3862b9de4901a6a5a92e0c7a6c0e011af433e379ba536aa3ed7b2c275c5a658bb3e98cd18e0740a9be13e18cdadfd2b75777c0c2624b8ac64975831ca67998a15cc66 }


condition:
	$a0
}