rule Win_Trojan_SMVB_2
{
strings:
	$a0 = { e8f6ffe87200c3e85203c3e82c02e8a802c38d0313136d130500640000016e1380fcdd742880fcde74273d004b }


condition:
	$a0
}