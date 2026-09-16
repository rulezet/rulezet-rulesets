rule Win_Trojan_Hymn_2
{
strings:
	$a0 = { cd213d3167750407e9ab0007b449cd }


condition:
	$a0
}