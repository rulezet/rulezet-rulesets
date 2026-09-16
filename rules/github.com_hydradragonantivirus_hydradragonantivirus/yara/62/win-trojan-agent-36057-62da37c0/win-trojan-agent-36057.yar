rule Win_Trojan_Agent_36057
{
strings:
	$a0 = { 33d2426a00ff15043040006a00ff15043040006a00ff1504304000 }


condition:
	$a0
}