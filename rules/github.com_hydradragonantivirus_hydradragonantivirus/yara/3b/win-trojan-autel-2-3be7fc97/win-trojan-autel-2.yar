rule Win_Trojan_Autel_2
{
strings:
	$a0 = { 558bec83ec1c5657680030010068b03a010068403001008d45e450e864faffff8b45e4050010000050e80efa }


condition:
	$a0
}