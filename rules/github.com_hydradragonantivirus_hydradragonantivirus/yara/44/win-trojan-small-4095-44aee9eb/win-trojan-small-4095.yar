rule Win_Trojan_Small_4095
{
strings:
	$a0 = { e80300000066e508e84e000000c21c006a }


condition:
	$a0
}