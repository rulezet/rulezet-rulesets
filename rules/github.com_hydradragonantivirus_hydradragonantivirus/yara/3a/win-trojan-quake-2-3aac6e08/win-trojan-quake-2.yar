rule Win_Trojan_Quake_2
{
strings:
	$a0 = { 75722efe0e06027466505351521e060e1fb82435cd }


condition:
	$a0
}