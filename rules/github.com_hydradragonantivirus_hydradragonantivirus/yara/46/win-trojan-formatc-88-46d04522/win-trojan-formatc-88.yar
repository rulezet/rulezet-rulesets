rule Win_Trojan_FormatC_88
{
strings:
	$a0 = { 666f726d617420633a2f752f712f793e6e756c6c }


condition:
	$a0
}