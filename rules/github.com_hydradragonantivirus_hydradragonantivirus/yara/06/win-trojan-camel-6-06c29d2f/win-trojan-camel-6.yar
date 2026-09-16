rule Win_Trojan_Camel_6
{
strings:
	$a0 = { cd2188d3b40bcd2180fc00750701eb2e3a07745f1e06b42c80f466bbffffcd2181eb2000b800 }


condition:
	$a0
}