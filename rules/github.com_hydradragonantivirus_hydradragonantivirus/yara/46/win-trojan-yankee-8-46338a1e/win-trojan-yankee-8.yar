rule Win_Trojan_Yankee_8
{
strings:
	$a0 = { 0e02002efe0e0300b4402e8b1e2d0033d2b99708fa9c2eff1e280073039ceb033bc19cbe5c00 }


condition:
	$a0
}