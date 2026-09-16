rule Win_Trojan_Irish_1
{
strings:
	$a0 = { 3939393939393939098bc98ad28bc0909c50f5fafc5af859f88bdbeb00fcbcf90efc51b9bc049e91918ae452f553fc9e0ebe4305908ac08bc98ad28bfeadf5fc9035ae08fa8bc08bdbeb0090abf9e2 }


condition:
	$a0
}