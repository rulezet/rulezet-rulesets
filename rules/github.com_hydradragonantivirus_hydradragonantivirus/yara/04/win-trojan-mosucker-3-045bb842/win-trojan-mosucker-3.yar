rule Win_Trojan_MoSucker_3
{
strings:
	$a0 = { 4c6f6164696e67204d6f5375636b65722039392e2e2e000400c000000578 }


condition:
	$a0
}