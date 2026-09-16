rule Win_Trojan_Small_193
{
strings:
	$a0 = { 0156568ec3bfe002faa674134e4fb156f3a4be84005626a526a55fb02eabab5f8d75568bcc2bce0e07f3a4c380fc }


condition:
	$a0
}