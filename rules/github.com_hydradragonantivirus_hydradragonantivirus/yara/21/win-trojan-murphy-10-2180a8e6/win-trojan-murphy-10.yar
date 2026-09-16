rule Win_Trojan_Murphy_10
{
strings:
	$a0 = { 1fc4064c002e8984b6fb2e8c84b8fb }


condition:
	$a0
}