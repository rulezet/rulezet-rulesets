rule Win_Trojan_BootSectorDr_1
{
strings:
	$a0 = { ba4b02fe0e5c00785fba6d01e8590032e4cd1624df3c5975538a165c0032e4cd137242ba2f02e83f00fcbe630484f675034974388d5c05bd0002ac3cf6740fbb }


condition:
	$a0
}