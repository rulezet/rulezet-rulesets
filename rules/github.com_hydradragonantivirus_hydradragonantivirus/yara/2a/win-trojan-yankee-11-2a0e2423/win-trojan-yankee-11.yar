rule Win_Trojan_Yankee_11
{
strings:
	$a0 = { 740583fcf072ec8cd8488ec026 }


condition:
	$a0
}