rule Win_Trojan_SubSeven_2
{
strings:
	$a0 = { 5150e8aaf34928540bed2efd2a2b6f21103a2fc2b9494f0b240d795945da698720a5bc444fbcb725048b778c212cf16b3005454e54b58653619cddeea899ddf0 }


condition:
	$a0
}