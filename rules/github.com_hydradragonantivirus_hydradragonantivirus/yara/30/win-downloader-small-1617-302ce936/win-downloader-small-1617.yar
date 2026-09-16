rule Win_Downloader_Small_1617
{
strings:
	$a0 = { 75c76c6da56e5d2aab016c92520f4c446f77e96c70af7854971aed1d468e687423703a2f886c6966cd }


condition:
	$a0
}