rule Win_Trojan_Kalah_4
{
strings:
	$a0 = { 2bc8740633d2b440cd2133c933d2b80242cd212ea384 }


condition:
	$a0
}