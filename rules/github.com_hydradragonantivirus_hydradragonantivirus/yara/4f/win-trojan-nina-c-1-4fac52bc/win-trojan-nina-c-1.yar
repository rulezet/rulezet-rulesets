rule Win_Trojan_Nina_C_1
{
strings:
	$a0 = { 4b750d505351521ee80a001f5a595b58ea }


condition:
	$a0
}