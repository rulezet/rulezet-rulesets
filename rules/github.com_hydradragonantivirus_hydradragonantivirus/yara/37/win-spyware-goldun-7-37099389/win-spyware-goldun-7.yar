rule Win_Spyware_Goldun_7
{
strings:
	$a0 = { e500501201007851010002a21675bda07d24321d33bd0020000000666f746f2e6a70672020 }


condition:
	$a0
}