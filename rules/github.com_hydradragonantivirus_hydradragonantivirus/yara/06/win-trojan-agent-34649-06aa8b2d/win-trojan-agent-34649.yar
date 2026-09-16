rule Win_Trojan_Agent_34649
{
strings:
	$a0 = { 6884494000e8eeffffff000040000000300000003800000000000000 }


condition:
	$a0
}