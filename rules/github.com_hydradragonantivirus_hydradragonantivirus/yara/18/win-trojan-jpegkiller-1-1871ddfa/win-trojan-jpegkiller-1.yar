rule Win_Trojan_JpegKiller_1
{
strings:
	$a0 = { 8becc7460264005d5feb08908db69b03eb079081ed0601ebf350558becc7460200015d5f57a5a48bfd8bef8b }


condition:
	$a0
}