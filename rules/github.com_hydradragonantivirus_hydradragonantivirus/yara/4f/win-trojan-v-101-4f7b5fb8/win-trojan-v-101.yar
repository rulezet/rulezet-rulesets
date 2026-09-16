rule Win_Trojan_V_101
{
strings:
	$a0 = { 3f8bf3ba8d038b1e7f03b92000cd218bdec3e89cffb440ba8d038bf38b1e7f03b92000cd218bde }


condition:
	$a0
}