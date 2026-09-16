rule Win_Trojan_L_26
{
strings:
	$a0 = { 018b161701b93501902e311483c602e80300e2f5c3c3b419cd2150b40eb202cd21b44732d28db6c603cd21bae001 }


condition:
	$a0
}