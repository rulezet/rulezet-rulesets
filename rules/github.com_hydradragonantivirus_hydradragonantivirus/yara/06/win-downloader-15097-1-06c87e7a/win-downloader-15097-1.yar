rule Win_Downloader_15097_1
{
strings:
	$a0 = { c055c5e8b6be15c56ad39d9fbcfa652d4d55b89256bf9a4c12d79c21b69dcd77ebe31632b98f26ef53f79c856fb9e33ac057f79d893f0ae7cc033a89d62add12 }


condition:
	$a0
}