rule Win_Trojan_Small_4259
{
strings:
	$a0 = { 7433008db6737363[0-100]43333333 }


condition:
	$a0
}