rule Win_Downloader_36214_1
{
strings:
	$a0 = { b9146a4500bab06945008bc3e88e30fdffb9586a4500b201a188904200e8e92ffdff8bd88d45fcba586a4500e892dafaff8d45f8ba7c6a4500e885dafaff }


condition:
	$a0
}