rule Win_Trojan_Small_4229
{
strings:
	$a0 = { 525283c404893c }


condition:
	$a0
}