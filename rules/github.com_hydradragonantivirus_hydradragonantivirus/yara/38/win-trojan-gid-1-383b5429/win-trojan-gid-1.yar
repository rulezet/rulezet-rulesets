rule Win_Trojan_GID_1
{
strings:
	$a0 = { 9e01b89001509a550e9e013dc8007403e9ff009acc011901bf7e4b1e57bf9f060e5731c050 }


condition:
	$a0
}