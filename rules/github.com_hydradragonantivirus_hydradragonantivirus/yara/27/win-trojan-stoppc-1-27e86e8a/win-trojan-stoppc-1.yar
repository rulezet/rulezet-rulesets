rule Win_Trojan_StopPC_1
{
strings:
	$a0 = { 0589019080e60203c2abc68686023090595ac35152b42ccd21e44086e0e44032e133c25a59 }


condition:
	$a0
}