rule Win_Trojan_Win_41
{
strings:
	$a0 = { 6c2066726f6d3a6e6f6e676d696e5f636e0a0000007263707420 }


condition:
	$a0
}