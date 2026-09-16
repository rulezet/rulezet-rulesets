rule Win_Trojan_V_63
{
strings:
	$a0 = { 2402c39c2eff1e8d00c33d004b740f3db14b7405ea }


condition:
	$a0
}