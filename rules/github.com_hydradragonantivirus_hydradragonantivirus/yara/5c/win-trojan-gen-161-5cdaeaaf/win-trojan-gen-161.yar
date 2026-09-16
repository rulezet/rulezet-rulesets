rule Win_Trojan_Gen_161
{
strings:
	$a0 = { 040e57e877fd8dbefefe1657bf03040e579a22016b00e8fafd89ec5dc30844756b652f534d46 }


condition:
	$a0
}