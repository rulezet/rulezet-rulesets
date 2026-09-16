rule Win_Spyware_Banker_2722
{
strings:
	$a0 = { ae0a77c8cecbc48e414e329f2314d4d2ee45958ac3589ebc752cd805a4ca2bc4de6d2a6dad70643a9448d2cc1c433970d932becfad2d9420fd6c36e2aed3ed1fb8c5cce1eb710ba2847633d53468 }


condition:
	$a0
}