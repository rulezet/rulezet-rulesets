rule Win_Trojan_Dikshev_8
{
strings:
	$a0 = { 86d90d87d6b440b90300cce8bc078dbe700ee81a01e8c507e89d078d96700e8bcf2bcab440cc }


condition:
	$a0
}