rule Win_Downloader_Agent_32880
{
strings:
	$a0 = { 8525443b12e8c93c7a862794fad4542a55f746ad7641038de55fe583d54eeb799f21424254d4697a37830cced6c607ae5d17b138446f0d11fc544eb6eeeb }


condition:
	$a0
}