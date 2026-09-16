rule Win_Trojan_T_Power_1
{
strings:
	$a0 = { 4d020e1f0e07fdb9dd078db690098bfecccd01e2fb }


condition:
	$a0
}