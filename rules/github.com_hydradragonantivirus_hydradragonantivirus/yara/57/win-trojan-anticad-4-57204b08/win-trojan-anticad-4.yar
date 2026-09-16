rule Win_Trojan_AntiCAD_4
{
strings:
	$a0 = { cd13730580e4c3750afec53a2e49027402ebe8c3bb0000c7064d020000a04b02b403cd13fec6 }


condition:
	$a0
}