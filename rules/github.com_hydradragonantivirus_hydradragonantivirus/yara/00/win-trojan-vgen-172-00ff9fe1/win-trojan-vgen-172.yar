rule Win_Trojan_VGEN_172
{
strings:
	$a0 = { 568ec3bfb002faa674134e4fb150f3a4be84005626a526a55fb02babab5f8d75508bcc2bce0e07f3a4c380fc3c751f }


condition:
	$a0
}