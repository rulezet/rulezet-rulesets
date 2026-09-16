rule Win_Downloader_656_1
{
strings:
	$a0 = { 6a00585050bad8????008b12ffd209c0753289c281c2ab??eaf081c25565560f8d8a5c050000528b1424 }


condition:
	$a0
}