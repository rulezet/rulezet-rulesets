rule Win_Downloader_Banload_1476
{
strings:
	$a0 = { db3aea4362d69ed8eeed0e1de26edfcbe497d6f65520ba112395a9c8681d98679328386c6a119ab91983a415527be1f264a8960bbf3e6e098d4e224f258d3d09920ce012 }


condition:
	$a0
}