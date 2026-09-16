rule Win_Trojan_T_1
{
strings:
	$a0 = { 33c9ba7501cd217227b8013dba9e00cd218bd8b44050b91200ba0001cd2158b96900ba8501cd21 }


condition:
	$a0
}