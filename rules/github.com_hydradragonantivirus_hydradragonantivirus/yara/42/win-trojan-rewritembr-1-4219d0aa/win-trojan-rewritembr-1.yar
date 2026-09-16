rule Win_Trojan_RewriteMBR_1
{
strings:
	$a0 = { b001b403ba8000b90100cd13b8004ccd21fa33c08ed0bc007c8bf45007501ffbfcbf0006b9 }


condition:
	$a0
}