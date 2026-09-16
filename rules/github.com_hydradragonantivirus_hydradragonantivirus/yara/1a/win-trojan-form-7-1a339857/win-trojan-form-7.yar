rule Win_Trojan_Form_7
{
strings:
	$a0 = { cd137213e82b00bbf903b801038b1653008b0e5100cd13c3 }


condition:
	$a0
}