rule Win_Trojan_Dreg_4
{
strings:
	$a0 = { 0400cc8dbed202ffd74490c979dd3c424bfe3c62b4ff387a49fe4e0b680b6807396ac7fe0cd8913195e2b37102a5b5 }


condition:
	$a0
}