rule Win_Trojan_RanDir_1
{
strings:
	$a0 = { 652f534d465d042e636f6d042e657865015c5589e581ec6817b80800509ae90c5c00408886 }


condition:
	$a0
}