rule Win_Trojan_Rajaat_6
{
strings:
	$a0 = { 5f03a1610305bc0283d200e860fe89167a03a37c03b440ba7803b94400e8dcfee957ff }


condition:
	$a0
}