rule Win_Trojan_Jerusalem_32
{
strings:
	$a0 = { 0c1181fd951e383690319ab9aa12b50374be74161538bc163f26b23834cc1442e90cb445ed161786 }


condition:
	$a0
}