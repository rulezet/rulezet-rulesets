rule Win_Trojan_Pentagon_3
{
strings:
	$a0 = { 597cb96c0030760045e2fa }


condition:
	$a0
}