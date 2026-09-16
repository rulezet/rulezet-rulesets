rule Win_Trojan_EndOf_1
{
strings:
	$a0 = { 02cd2172cb39c875c7c3b440b90600cd2172bd39c875b9c3b440ba0001b91403cd2172ac39c8 }


condition:
	$a0
}