rule Win_Trojan_DBF_2
{
strings:
	$a0 = { c981c1000081e911008ed933f68d1e2c01b93f049080300e46e2fa }


condition:
	$a0
}