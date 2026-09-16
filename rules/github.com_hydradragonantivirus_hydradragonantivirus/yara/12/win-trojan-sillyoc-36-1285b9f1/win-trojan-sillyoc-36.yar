rule Win_Trojan_SillyOC_36
{
strings:
	$a0 = { b431b00133c9ba9e00e88e01b44fb002e8870193b44dba1203b90300e87b01be1203803ce8 }


condition:
	$a0
}