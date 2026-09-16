rule possible_mask_reset_used_in_arithmetic_compression__8_byt_9_
{
strings:
	$a0 = { 0080c0e0f0f8fcfeff }

condition:
	$a0
}