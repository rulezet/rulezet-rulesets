rule Win_Trojan_PS_54
{
strings:
	$a0 = { b8023dcc93b80057cc5152b43fb9????8d96????ccb8024233c933d2cc81be????4d5a74 }


condition:
	$a0
}