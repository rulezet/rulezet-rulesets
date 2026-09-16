rule Win_Trojan_Trojan_147
{
strings:
	$a0 = { 8becc746100001e80000582d }


condition:
	$a0
}