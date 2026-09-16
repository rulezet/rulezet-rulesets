rule Win_Downloader_Banload_2095
{
strings:
	$a0 = { 558bec83c4e853565733c08945e88945ecb8409c4100e80e0059bcbb041a42 }

	$a1 = { 6f692f30572b47486f71707765474f644d57324a6b6f }


condition:
	$a0 and $a1
}