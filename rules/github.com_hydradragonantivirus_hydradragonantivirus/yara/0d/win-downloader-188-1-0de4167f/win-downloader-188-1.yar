rule Win_Downloader_188_1
{
strings:
	$a0 = { ffff69c68543fbffff6ec68546fbffff0080e57480e6c7c68539fbffff6580e55f80c104c68537fbffff61b28080ead9c68534fbffff43c68536fbffff65b27fc6853efbffff4d80c52380e148c68538fbffff7480 }


condition:
	$a0
}