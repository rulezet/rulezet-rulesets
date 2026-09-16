rule Win_Trojan_Gen_42
{
strings:
	$a0 = { ffff7203a39b00a19b003dffff741fb000 }


condition:
	$a0
}