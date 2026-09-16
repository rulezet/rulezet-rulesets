rule Win_Trojan_Christmas_6
{
strings:
	$a0 = { bf00008bf2acb90080f2aeb90400acae75 }


condition:
	$a0
}