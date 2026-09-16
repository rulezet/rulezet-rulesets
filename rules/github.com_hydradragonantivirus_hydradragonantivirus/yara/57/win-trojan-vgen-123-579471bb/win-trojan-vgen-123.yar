rule Win_Trojan_VGEN_123
{
strings:
	$a0 = { 1600b6b1b9b6b3abadbeabb0ad0004010c0c0104009090905e83ee03b430bb69698bcbcd21b930015156fc80fcff74 }


condition:
	$a0
}