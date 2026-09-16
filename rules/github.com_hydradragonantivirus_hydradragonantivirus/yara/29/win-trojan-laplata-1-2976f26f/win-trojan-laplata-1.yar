rule Win_Trojan_Laplata_1
{
strings:
	$a0 = { 03cd21724c890e0b00b80144feccb90000cd21723cb8006dfeccbb0102b90000ba0200be8f03 }


condition:
	$a0
}