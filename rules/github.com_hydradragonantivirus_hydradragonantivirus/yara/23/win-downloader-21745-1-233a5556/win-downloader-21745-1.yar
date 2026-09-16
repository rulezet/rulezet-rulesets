rule Win_Downloader_21745_1
{
strings:
	$a0 = { 81c490000000b30183ec446a11590fb6c38bfc5083ec448d75acf3a56a11598bfc8d75ac50f3a5e825feffff81c4900000005f5e8ac35bc9c3 }


condition:
	$a0
}