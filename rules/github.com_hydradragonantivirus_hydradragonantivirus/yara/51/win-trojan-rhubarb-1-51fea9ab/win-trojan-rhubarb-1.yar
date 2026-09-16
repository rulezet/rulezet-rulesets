rule Win_Trojan_Rhubarb_1
{
strings:
	$a0 = { d221cdb5b204f2ec566cec58f65dec59ecba21cdb22fc7be84998e8d9e8ecc9addc2dcc75dec54edaf617819ec070cba04efeccd215ebd41ff80b2c800ec4575f8 }


condition:
	$a0
}