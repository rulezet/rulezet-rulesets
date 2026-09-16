rule Win_Trojan_B_83
{
strings:
	$a0 = { fba11304b106d3e02de0078ec0832e130404be007c89f7b90001f3a506b8647c50cb }


condition:
	$a0
}