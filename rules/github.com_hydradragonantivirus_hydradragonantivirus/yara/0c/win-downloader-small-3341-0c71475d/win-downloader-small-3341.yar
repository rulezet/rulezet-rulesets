rule Win_Downloader_Small_3341
{
strings:
	$a0 = { 8d44240c50518bcc8964241c68cc324000e88b0c00008bcee8f801000085c0750968d0070000ffd7ebd6 }


condition:
	$a0
}