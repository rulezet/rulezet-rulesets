rule Win_Trojan_Vundo_41
{
strings:
	$a0 = { 60e81b1c0000116493a45ab9654cb20a7e0000 }


condition:
	$a0
}