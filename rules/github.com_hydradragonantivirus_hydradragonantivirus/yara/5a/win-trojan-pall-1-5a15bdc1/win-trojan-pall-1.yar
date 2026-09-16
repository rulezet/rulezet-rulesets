rule Win_Trojan_Pall_1
{
strings:
	$a0 = { b80b008ed88ec0b871008ed8b98001be0400bf6300f3a5b80b008ed88ec0bb000380bf6300007404fe8f63004b }


condition:
	$a0
}