rule Win_Trojan_Abraxas_6
{
strings:
	$a0 = { 0f00e85400e87100e84e00e87500e8d700beb9048b1c0bdb743eb8dd34ba12003bd3732ff7f38b }


condition:
	$a0
}