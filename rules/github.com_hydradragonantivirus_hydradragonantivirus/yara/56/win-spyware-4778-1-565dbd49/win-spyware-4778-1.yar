rule Win_Spyware_4778_1
{
strings:
	$a0 = { 560f00ce5e6081c76553464f }


condition:
	$a0
}