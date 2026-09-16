rule Win_Downloader_Small_687
{
strings:
	$a0 = { 68a811400068e8114000a1102040008b0050e867feffffffd0e8e4feffff633a5c626f6f742e65786500687474703a2f }


condition:
	$a0
}