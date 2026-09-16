rule Win_Trojan_MGUL_1
{
strings:
	$a0 = { 2800fa8ed2bc1e01fb5053515657e800005b8db7f5062e89b736012e807cff007511bf0001a5a52ec744fc00012e8c }


condition:
	$a0
}