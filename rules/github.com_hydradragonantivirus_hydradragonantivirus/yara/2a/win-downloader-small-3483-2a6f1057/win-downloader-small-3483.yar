rule Win_Downloader_Small_3483
{
strings:
	$a0 = { f90b8c4d71d6d47fda5f4cf0d69fe43de4feee8dfa28ee12f5096e80630d690e48d29b100e90c0f7559be91fdc4867c75def3a51916c1be587cc38a4db3e8e10873b8316dc1fc6d4d698cbb4a012 }


condition:
	$a0
}