rule Win_Trojan_Tiny_85
{
strings:
	$a0 = { 9090eb01eaba0001fbeb01eab9d20190eb01eacd2133c9eb01eab8004290eb01ea33d2cd21eb }


condition:
	$a0
}