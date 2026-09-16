rule Win_Trojan_Agent_35370
{
strings:
	$a0 = { 3c3f706870202f2a20667832396964202a2f206563686f28 }


condition:
	$a0
}