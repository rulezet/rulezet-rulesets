rule Win_Trojan_ExeHeader_4
{
strings:
	$a0 = { 0103569c0ee871ff2bc0b90400fc8b7f08d3e78d39807f18407330813dbc4ee12bf6c2807405b1 }


condition:
	$a0
}