rule Win_Trojan_Baluade_1
{
strings:
	$a0 = { 010100558e02000000ffffcd15000086020000020000000903 }


condition:
	$a0
}