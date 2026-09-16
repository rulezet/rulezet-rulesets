rule Win_Downloader_Small_1937
{
strings:
	$a0 = { 837d0c017540ff75088f05ec35001068dc3500106a016a00e859000000a344360010 }


condition:
	$a0
}