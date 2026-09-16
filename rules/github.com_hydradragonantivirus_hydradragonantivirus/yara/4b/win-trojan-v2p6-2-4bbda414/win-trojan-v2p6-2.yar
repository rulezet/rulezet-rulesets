rule Win_Trojan_V2P6_2
{
strings:
	$a0 = { f8f9b9d307baa7f3fc9033f6bd270290311290454ae2f8 }


condition:
	$a0
}