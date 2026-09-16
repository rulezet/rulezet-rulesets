rule Win_Trojan_Exe_2
{
strings:
	$a0 = { 5d81ed0300b8dd4bcd213d4bdd74691eb44abbffffcd2183eb2490b44a }


condition:
	$a0
}