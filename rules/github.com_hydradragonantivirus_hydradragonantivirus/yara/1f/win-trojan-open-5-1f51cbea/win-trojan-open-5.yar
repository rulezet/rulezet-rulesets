rule Win_Trojan_Open_5
{
strings:
	$a0 = { 894515b440b9270633d2e89000e8fc00eb8d837c1a }


condition:
	$a0
}