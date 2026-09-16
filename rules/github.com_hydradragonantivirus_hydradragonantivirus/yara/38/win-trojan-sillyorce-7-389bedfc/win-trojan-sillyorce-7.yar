rule Win_Trojan_SillyORCE_7
{
strings:
	$a0 = { cd21bf3201891d8c4502b425ba2c01cd21b235cd27b8013c33c9cd21930e1fb44099fec6b132cd21cf80fc4b74 }


condition:
	$a0
}