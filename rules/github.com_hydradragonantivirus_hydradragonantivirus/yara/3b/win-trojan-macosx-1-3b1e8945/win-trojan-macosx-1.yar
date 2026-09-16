rule Win_Trojan_MacOSX_1
{
strings:
	$a0 = { 2f55736572732f6170706c652f446f63756d656e74732f6d6163206261636b }


condition:
	$a0
}