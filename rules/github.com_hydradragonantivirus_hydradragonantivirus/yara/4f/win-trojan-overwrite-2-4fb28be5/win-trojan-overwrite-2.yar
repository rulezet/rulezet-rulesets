rule Win_Trojan_Overwrite_2
{
strings:
	$a0 = { 21c00b9a3f02360009c0740731c09ae9003600bf4c201e57bf44001e57ff368621bf58211e }


condition:
	$a0
}