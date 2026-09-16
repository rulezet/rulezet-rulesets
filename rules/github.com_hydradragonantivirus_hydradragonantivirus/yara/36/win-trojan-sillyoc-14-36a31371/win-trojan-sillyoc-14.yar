rule Win_Trojan_SillyOC_14
{
strings:
	$a0 = { 3d8d541e52cd2193b440b92200ba0001cd21b440b98400baa601cd215ab80143b90100cd21b4 }


condition:
	$a0
}