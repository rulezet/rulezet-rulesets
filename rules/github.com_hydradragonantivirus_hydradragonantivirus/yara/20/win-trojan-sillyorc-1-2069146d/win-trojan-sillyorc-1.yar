rule Win_Trojan_SillyORC_1
{
strings:
	$a0 = { 30cd213d05007538b82b35cd218c062601b021cd2106583d60007424b860008ec00e1f33ffbe0001b16bfcf3a4b860 }


condition:
	$a0
}