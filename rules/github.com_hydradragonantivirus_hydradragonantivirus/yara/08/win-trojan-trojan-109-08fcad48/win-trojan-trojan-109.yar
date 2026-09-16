rule Win_Trojan_Trojan_109
{
strings:
	$a0 = { f6485a88c5b10133dbb80302b6018a16907ccd138cc005200050680503cb }


condition:
	$a0
}