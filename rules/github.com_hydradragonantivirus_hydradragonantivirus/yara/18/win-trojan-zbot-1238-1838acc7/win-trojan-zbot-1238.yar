rule Win_Trojan_Zbot_1238
{
strings:
	$a0 = { 8bd5558bec83ec7081eaab1a521a25bae4242803c681c91e63ea3a33c381fa34 }


condition:
	$a0
}