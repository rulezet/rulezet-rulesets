rule Win_Downloader_61708_1
{
strings:
	$a0 = { 837c2408017505e805005c92ff7424048b4c24108b54240ce80500341659c20c00cccccccccc }


condition:
	$a0
}