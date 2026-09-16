rule Win_Trojan_CAZ_1
{
strings:
	$a0 = { 720783660afeeb0890834e0a01eb239050b42f9c2eff }


condition:
	$a0
}