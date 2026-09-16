rule Win_Downloader_326_1
{
strings:
	$a0 = { 83ec38535657b90d000000becc2040008d7c240cf3a533dba433c0eb038d4900 }


condition:
	$a0
}