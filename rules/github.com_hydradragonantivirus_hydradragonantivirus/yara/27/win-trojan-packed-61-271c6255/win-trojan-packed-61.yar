rule Win_Trojan_Packed_61
{
strings:
	$a0 = { b8f0b747005064 }

	$a1 = { fef6f1fffdf4effffdf3edffe1b99cff604830ff0000000000000000d17d57fff1beaafffefbfaffd28b71ffb37d66ffda9c83ffd97647ff8a4b26ffc16e4affc7836affb46238ff553b15ffeadcd6fff8eeeaffda9c83ff8f4415fffffefefffffefdfff3caaaffd9a988ffdfb292ff }


condition:
	$a0 and $a1
}