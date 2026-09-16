rule Win_Trojan_BJK_1
{
strings:
	$a0 = { bafa0ab8400086e0e8ad01b8420086e0ba260033c9e8a001b8420086e0ba060233c9e89301 }


condition:
	$a0
}