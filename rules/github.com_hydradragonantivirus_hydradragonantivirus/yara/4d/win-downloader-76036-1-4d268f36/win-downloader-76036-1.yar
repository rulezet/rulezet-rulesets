rule Win_Downloader_76036_1
{
strings:
	$a0 = { 676574[0-41]222e2469702e225c72 }

	$a1 = { 2e7472696d[0-20]7970653b373737373b }

	$a2 = { 653d222f746d702f222e245f3b }


condition:
	$a0 and $a1 and $a2
}