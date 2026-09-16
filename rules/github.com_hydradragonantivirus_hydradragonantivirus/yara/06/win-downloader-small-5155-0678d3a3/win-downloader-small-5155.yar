rule Win_Downloader_Small_5155
{
strings:
	$a0 = { 214a017201ed000727f41ed2706b60063c13e738e16701f2f7a93afb61b3c1f870acf70a72e6feca76fef4f85753829fbf6efc0b76e4edea54f68e7797ffba15539ddc0b7667 }


condition:
	$a0
}