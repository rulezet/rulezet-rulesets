rule Win_Trojan_Camel_1
{
strings:
	$a0 = { 93029201b8024233c999cd21b440b992018d960301cd21b800578b96c3028b8ec102050100cd }


condition:
	$a0
}