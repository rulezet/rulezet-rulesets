rule Win_Downloader_Banload_597
{
strings:
	$a0 = { e4aa35446925dd4aa78a3a0c54e6cff33fed107389e22d896aabfb15f6fa6b9f00b50f51817fcf94109acf7cc4a0e715adb53bfa098d240d50a3bf5124bde00f26d3e542 }


condition:
	$a0
}