rule Win_Trojan_PcClient_56
{
strings:
	$a0 = { 5933c08dbdd2fdfffff3ab66ab6a3f5933c08dbdd2fefffff3ab66ab6a075933c08d7ddaf3ab6a5c5966ab6a6558ff750866898dd0feffff68 }


condition:
	$a0
}