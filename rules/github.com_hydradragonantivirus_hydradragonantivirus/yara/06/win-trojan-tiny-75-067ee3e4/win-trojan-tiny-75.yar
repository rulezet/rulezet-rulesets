rule Win_Trojan_Tiny_75
{
strings:
	$a0 = { 010181c603015b0ebf000157fc8a847b01aa8b847c01abbb54008ec326813e00002e8b740ebf0000b98d01fcf3 }


condition:
	$a0
}