rule Win_Downloader_Small_1179
{
strings:
	$a0 = { 6e74697370792e657865000025735c33642d706f6c69732e657865007262 }


condition:
	$a0
}