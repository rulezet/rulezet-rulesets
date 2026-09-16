rule Win_Trojan_DarthVader_8
{
strings:
	$a0 = { 8936f000a3fe0031c08ed88e06ae00b8 }


condition:
	$a0
}