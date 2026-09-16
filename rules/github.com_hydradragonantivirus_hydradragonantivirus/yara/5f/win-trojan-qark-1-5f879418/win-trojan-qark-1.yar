rule Win_Trojan_Qark_1
{
strings:
	$a0 = { 83ee0306560e1f0e078b9c040081c626008bfeb9e403fcad03c3abe2fa5e07 }


condition:
	$a0
}