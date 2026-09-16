rule Win_Trojan_Companion_5
{
strings:
	$a0 = { 720f93b440b98000ba0001cd21b43ecd21b44febdf }


condition:
	$a0
}