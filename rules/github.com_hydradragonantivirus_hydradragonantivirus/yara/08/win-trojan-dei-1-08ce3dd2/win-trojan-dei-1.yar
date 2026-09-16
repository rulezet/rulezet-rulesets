rule Win_Trojan_DEI_1
{
strings:
	$a0 = { 723826894515e83601baf807b91c00b440e803fd26c745150000ba9707b440b91600e8f2fc }


condition:
	$a0
}