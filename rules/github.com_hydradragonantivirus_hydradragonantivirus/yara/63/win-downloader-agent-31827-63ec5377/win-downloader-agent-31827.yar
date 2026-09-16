rule Win_Downloader_Agent_31827
{
strings:
	$a0 = { 8d8dfcf9ffff516858e040006802000080ff1500c0400085c0740583c8ffeb74 }


condition:
	$a0
}