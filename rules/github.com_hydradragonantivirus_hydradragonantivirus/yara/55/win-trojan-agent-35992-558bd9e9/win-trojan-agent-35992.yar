rule Win_Trojan_Agent_35992
{
strings:
	$a0 = { 9055572e[0-200]414949904151414949904154e9 }


condition:
	$a0
}