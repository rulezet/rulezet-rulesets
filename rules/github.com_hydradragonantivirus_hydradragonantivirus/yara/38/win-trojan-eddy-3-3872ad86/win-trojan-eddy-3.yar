rule Win_Trojan_Eddy_3
{
strings:
	$a0 = { 5488441233d2b9ca05b440cd21b000e8d400bace05b91800b440cd21e90eff32c0cf56b42ccd21 }


condition:
	$a0
}