rule Win_Adware_Surfside_2
{
strings:
	$a0 = { 6e5c52756e00000053757266536964654b69636b203300005468 }


condition:
	$a0
}