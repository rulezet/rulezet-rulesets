rule Win_Trojan_Australian_4
{
strings:
	$a0 = { 8fbd74616096966dcb918ad0a8aba483a09bd3755fb9aa03f10ea2b703b7b47a90b1aa847b23d52e }


condition:
	$a0
}