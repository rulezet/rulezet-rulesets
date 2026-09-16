rule Win_Downloader_267_1
{
strings:
	$a0 = { 251926552aef51df78cda4e7f48cf39ca4acda1cee2ec73055ec2a6f5676eb80952d88344fb44ecf69d69ab0fd8d7b9da5b5bfbe9c9e5de1c921dc149a5f5f0569861e8313b91b628aee5e6d0d0e }


condition:
	$a0
}