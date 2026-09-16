rule Win_Trojan_N_4
{
strings:
	$a0 = { 86058db61c00b9b20231144646e2fac3e800005d81edbf05eb00c3 }


condition:
	$a0
}