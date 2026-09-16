rule Win_Trojan_VB_1746
{
strings:
	$a0 = { 736f6c75626c656e65737300070000004cbe40000700000000be400007 }


condition:
	$a0
}