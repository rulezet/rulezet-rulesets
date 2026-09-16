rule Win_Trojan_Jerusalem_36
{
strings:
	$a0 = { 7505b800039dcf80fcde742d80fcdd }


condition:
	$a0
}