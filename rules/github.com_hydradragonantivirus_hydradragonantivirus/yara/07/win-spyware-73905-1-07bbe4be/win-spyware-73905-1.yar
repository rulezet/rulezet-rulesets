rule Win_Spyware_73905_1
{
strings:
	$a0 = { ff15????410083f80075195089e05068fb0000005050ff156430 }


condition:
	$a0
}