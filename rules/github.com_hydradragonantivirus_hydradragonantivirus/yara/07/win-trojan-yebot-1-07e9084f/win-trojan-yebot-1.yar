rule Win_Trojan_Yebot_1
{
strings:
	$a0 = { 2e68746d6c3f623d255826633d257326673d257500550053 }


condition:
	$a0
}