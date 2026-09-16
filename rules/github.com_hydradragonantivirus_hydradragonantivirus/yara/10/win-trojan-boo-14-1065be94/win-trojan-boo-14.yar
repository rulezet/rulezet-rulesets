rule Win_Trojan_BOO_14
{
strings:
	$a0 = { 122c20d3e0b9b901fc8ec0f3a4be4c00a5a58944fec744fc2e7dff0e13042bc099cd13cd199c }


condition:
	$a0
}