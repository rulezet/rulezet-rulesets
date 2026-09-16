rule Win_Trojan_Icelandic_5
{
strings:
	$a0 = { 03a32400a16a03051000a31c0090 }


condition:
	$a0
}