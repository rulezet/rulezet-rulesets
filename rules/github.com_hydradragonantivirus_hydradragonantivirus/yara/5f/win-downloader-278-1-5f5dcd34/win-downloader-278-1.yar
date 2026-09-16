rule Win_Downloader_278_1
{
strings:
	$a0 = { 3c7a413fcc8362d3c984420743f07aac0f3b1104b5fd39da32ca1cc4c095b03659b7e19ed631acecf1ba54164f8299ce7cc4be6594c105ba127cfc271e75e91b9eeeb5bcabe61cbc4d4a94bc70b9 }


condition:
	$a0
}