rule Win_Trojan_Vienna_98
{
strings:
	$a0 = { 0300bf0001f3a48bfaba120003d7b41acd2132db83ea }


condition:
	$a0
}