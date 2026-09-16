rule Win_Trojan_DOS_206
{
strings:
	$a0 = { b403ba8000b90100b001bb0002cd13 }


condition:
	$a0
}