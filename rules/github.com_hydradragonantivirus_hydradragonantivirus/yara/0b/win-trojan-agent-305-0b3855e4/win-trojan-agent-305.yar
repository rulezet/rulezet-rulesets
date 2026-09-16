rule Win_Trojan_Agent_305
{
strings:
	$a0 = { 1000b90e022e81370e1283c302e2f6 }


condition:
	$a0
}