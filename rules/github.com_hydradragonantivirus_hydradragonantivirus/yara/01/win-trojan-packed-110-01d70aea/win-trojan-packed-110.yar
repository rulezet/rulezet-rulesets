rule Win_Trojan_Packed_110
{
strings:
	$a0 = { 22aa45e50ea245e526e6b8d0226245e5eff649240b31a2c40bd1a2e517f2ae851792aea517b2ae4526e6b9d81752ae65 }


condition:
	$a0
}