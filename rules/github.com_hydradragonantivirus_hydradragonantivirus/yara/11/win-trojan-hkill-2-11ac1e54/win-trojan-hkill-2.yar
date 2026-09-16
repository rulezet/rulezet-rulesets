rule Win_Trojan_HKill_2
{
strings:
	$a0 = { 6c20616e64204b696c6c2039380d0a24cd209090e900002eea0000000000000000505657 }


condition:
	$a0
}