rule Win_Downloader_24730_1
{
strings:
	$a0 = { 68204e0000e81ff8ffff6a006a0068dc7f4000a194924000506a00e849ffffffbaf07f4000b804804000e892d4ffff6a006810804000e8fec5ffff }


condition:
	$a0
}