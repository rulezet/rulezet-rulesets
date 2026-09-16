rule Win_Downloader_Small_3220
{
strings:
	$a0 = { cf2ebef5cfa59b58af413b7b10a6ba35af40827d57a04f7fb3693073416f3d81865cc0cf11ac3082b7c31b68976e514f5d8429455fc47b3adc312f3c59cf2d585be47b380cac }


condition:
	$a0
}