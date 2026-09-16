rule Win_Trojan_Small_4482
{
strings:
	$a0 = { 54588b401c8d80????77045068623435 }


condition:
	$a0
}