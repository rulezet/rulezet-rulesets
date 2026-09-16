rule Win_Trojan_DocStealer_1
{
strings:
	$a0 = { 42414e44454c20544845524d414c20504f5745522053544154494f4e }


condition:
	$a0
}