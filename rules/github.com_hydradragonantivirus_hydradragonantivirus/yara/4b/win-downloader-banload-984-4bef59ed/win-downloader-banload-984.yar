rule Win_Downloader_Banload_984
{
strings:
	$a0 = { 814b9f18964c360b5487a627d404ae1b337a4a92c7c999fcc767e855c9b4c09ae42115a1f325fa04ee9c422c77dd19a964e330cf2458b5a134e26ea4bbc1198fba27ff21f8bb9fde244db9ca5fcdf662 }


condition:
	$a0
}