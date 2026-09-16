rule Win_Trojan_FormatC_92
{
strings:
	$a0 = { 406563686f206f666620666f726d6174202f6175746f7465737420633a2f71 }


condition:
	$a0
}