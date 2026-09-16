rule Win_Trojan_Dashikut_1
{
strings:
	$a0 = { 72656773767233322532302f7325323073637272756e2e646c6c }


condition:
	$a0
}