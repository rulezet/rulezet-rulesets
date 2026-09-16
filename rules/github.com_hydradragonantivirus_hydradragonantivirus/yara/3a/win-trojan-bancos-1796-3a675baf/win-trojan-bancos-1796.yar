rule Win_Trojan_Bancos_1796
{
strings:
	$a0 = { 2fb7134d89be53b27f873a519d714286bb6a428fa1133ff93686296df2fcc614e9a8b490fb05d96fb6aaf102a09058cab1ea91f239beef7716944de88d3894f0b27ffc8f7594 }


condition:
	$a0
}