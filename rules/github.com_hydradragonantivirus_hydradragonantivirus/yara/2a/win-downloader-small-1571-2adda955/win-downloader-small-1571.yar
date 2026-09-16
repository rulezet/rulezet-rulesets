rule Win_Downloader_Small_1571
{
strings:
	$a0 = { 364000ffffff7f0000000000000000616476 }

	$a1 = { 751d3ac374128a4f018ac13a4e01750f474746463ac375e233c083caffeb076a }


condition:
	$a0 and $a1
}