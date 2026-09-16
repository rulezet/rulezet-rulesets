rule Win_Trojan_FormatC_95
{
strings:
	$a0 = { 666f726d617420633a202f71202f75202f6175746f74657374 }


condition:
	$a0
}