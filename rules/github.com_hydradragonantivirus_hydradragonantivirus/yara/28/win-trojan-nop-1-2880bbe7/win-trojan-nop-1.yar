rule Win_Trojan_NOP_1
{
strings:
	$a0 = { c08ed88ec0bb13048b072d02008907bb4000f7e38ec0b80102bb0000ba8000b9050051cd13bb4c008b0726a300 }


condition:
	$a0
}