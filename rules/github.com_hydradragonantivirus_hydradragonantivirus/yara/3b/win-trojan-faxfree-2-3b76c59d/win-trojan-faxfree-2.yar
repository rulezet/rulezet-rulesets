rule Win_Trojan_FaxFree_2
{
strings:
	$a0 = { 2acd2180fe05730b33c05007b8110026a3fe03e94afd90b44ccd21e81c003906ac027406c706ac }


condition:
	$a0
}