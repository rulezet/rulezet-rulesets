rule Win_Downloader_6365_1
{
strings:
	$a0 = { 53555633db575368fc20400068ec204000e812feffff68cc204000688c204000687c204000e8fefdffff }


condition:
	$a0
}