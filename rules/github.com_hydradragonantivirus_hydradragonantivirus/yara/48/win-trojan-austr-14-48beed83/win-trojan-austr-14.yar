rule Win_Trojan_Austr_14
{
strings:
	$a0 = { 40ba0001b9710103160101cd21b93c00be34020336010180340146e2fa }


condition:
	$a0
}