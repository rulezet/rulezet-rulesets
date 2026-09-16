rule Win_Downloader_Small_1182
{
strings:
	$a0 = { e583ec1056538b450831db8b0031f68b003d910000c077163d8d0000c0736f3d050000c07428e9 }

	$a1 = { 61746865722e636f6d7c2f }


condition:
	$a0 and $a1
}