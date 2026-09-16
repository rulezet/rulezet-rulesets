rule Win_Trojan_HAL_2862_1
{
strings:
	$a0 = { abaaf7f12e8997740b585b595a1f5ec3535152e800005b81eba50b2e8b87740bb9acaaf7e10571 }


condition:
	$a0
}