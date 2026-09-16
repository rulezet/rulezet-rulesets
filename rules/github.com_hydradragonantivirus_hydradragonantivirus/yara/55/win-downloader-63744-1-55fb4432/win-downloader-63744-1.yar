rule Win_Downloader_63744_1
{
strings:
	$a0 = { b8081b0000e8860f000053555657b9ff }

	$a1 = { 4f70656e }

	$a2 = { 77676574 }

	$a3 = { 257365727435256c752e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}