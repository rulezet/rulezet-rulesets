rule Win_Trojan_Philis_136
{
strings:
	$a0 = { 81eb3434592e81c33434592e895c24fc }


condition:
	$a0
}