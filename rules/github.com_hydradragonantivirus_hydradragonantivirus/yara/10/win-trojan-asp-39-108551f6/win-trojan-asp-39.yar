rule Win_Trojan_ASP_39
{
strings:
	$a0 = { 636d642e657865[0-21]222f63222b636d6431[0-38]b4f2bfaad6d8b6a8cff2[0-244]636d646f75742e6b696c6c }


condition:
	$a0
}