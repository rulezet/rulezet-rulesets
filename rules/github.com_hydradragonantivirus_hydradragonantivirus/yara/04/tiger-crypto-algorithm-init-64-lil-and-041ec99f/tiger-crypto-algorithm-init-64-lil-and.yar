rule Tiger_crypto_algorithm_init__64_lil_AND_
{
strings:
	$a0 = { efcdab8967452301[0-20]1032547698badcfe[0-20]87e1b2c3b4a596f0 }

condition:
	$a0
}