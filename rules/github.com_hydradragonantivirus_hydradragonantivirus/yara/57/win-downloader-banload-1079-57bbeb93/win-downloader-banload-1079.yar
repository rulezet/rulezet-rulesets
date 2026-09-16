rule Win_Downloader_Banload_1079
{
strings:
	$a0 = { 555ef8cde87585293aebc61c8885156cdba5501b934b343ad46577ae868c7bfa83085e6fe6b674325ccdeb8edde0da06a1b1e7f4240860bea7ccb4cc16c65050b11f1066 }


condition:
	$a0
}