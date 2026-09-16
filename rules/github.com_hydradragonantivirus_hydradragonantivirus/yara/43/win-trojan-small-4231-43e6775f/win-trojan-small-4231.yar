rule Win_Trojan_Small_4231
{
strings:
	$a0 = { 2bd603d6f7d22bd603 }


condition:
	$a0
}