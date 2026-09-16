rule Win_Trojan_Pysk_2
{
strings:
	$a0 = { 1301b4aacd2180fcbb7503e9ba001e061e0e1f32c088842a0288842b0288842c02b82135cd218c841402899c12 }


condition:
	$a0
}