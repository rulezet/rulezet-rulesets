rule Win_Trojan_Vienna_41
{
strings:
	$a0 = { 01a0dc022ea20101a0dd022ea20201b99000bb00002e }


condition:
	$a0
}