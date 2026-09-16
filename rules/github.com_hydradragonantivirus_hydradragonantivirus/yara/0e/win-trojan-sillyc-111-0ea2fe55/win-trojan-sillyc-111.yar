rule Win_Trojan_SillyC_111
{
strings:
	$a0 = { d1b80242cd215ab9e000b440cd21b43ecd21ba8000 }


condition:
	$a0
}