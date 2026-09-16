rule Win_Downloader_Delf_1090
{
strings:
	$a0 = { 89985a66da9863f620becb104735c9b65b53f149d2f0a161df178acc46540aabbe0db7ebe1e07cb4a7162d41fbd3f78f22df66ed484c56236750e8b0b5a16c855bc12ca39ba9344c41d149fb1fe9d3a6 }


condition:
	$a0
}