rule Win_Downloader_VB_403
{
strings:
	$a0 = { 142ba09adb09d7100f6ccba0c5eb436b3eac6b394d39b18686085414250c6143ac041e133fdc8a2788063da6b112084cc3a499da277f47f9f413bbd1e7f717f41f }


condition:
	$a0
}