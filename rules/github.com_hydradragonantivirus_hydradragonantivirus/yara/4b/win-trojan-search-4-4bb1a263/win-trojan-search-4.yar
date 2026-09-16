rule Win_Trojan_Search_4
{
strings:
	$a0 = { 0600000000000000e800005ec484cb00a300018c060201c684d30061b41a }


condition:
	$a0
}