rule Win_Trojan_FormatC_83
{
strings:
	$a0 = { 6563686f20666f726d617420??3a202f71203e3e20??3a6175746f657865632e626174 }


condition:
	$a0
}