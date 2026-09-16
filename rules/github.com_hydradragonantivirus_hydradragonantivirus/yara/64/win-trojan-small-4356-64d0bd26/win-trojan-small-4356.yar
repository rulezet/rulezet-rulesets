rule Win_Trojan_Small_4356
{
strings:
	$a0 = { 60e8??0000[0-255]545d31c00588ad37322d88373732505e01de }


condition:
	$a0
}