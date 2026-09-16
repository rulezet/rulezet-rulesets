rule Win_Trojan_Vengence_F_1
{
strings:
	$a0 = { 09b805feebfc80c43bebf40e1fba8c03b80125cd21b0 }


condition:
	$a0
}