rule Win_Spyware_5443_1
{
strings:
	$a0 = { 81ee1b44591981c61b4459 }


condition:
	$a0
}