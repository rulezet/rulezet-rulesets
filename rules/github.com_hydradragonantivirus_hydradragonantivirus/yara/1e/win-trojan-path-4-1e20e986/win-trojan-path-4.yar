rule Win_Trojan_Path_4
{
strings:
	$a0 = { ff03ddb9f60351bf0501e879ff03 }


condition:
	$a0
}