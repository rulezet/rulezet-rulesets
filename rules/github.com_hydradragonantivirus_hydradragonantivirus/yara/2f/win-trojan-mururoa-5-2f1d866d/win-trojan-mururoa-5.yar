rule Win_Trojan_Mururoa_5
{
strings:
	$a0 = { e207eb21905eeb1f902e3014eb1490b92500eb08902e8a948609ebf381c68709ebe746ebdb }


condition:
	$a0
}