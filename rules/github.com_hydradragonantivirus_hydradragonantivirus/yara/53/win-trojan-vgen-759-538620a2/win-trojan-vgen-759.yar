rule Win_Trojan_VGEN_759
{
strings:
	$a0 = { 2615b95b02bf6006311d310d47e2f9c03b6dd66666e9d3ea629cc4dac7e44db75a45293502701d7272b3c92f3ac12c }


condition:
	$a0
}