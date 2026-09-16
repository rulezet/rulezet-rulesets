rule Win_Spyware_530_1
{
strings:
	$a0 = { 36fd2918fbcfc62287ca0f8140cbd620899ac578dae8edb707e6c960d5dabc93903a986fb881f7a0de8c82244ff6c0e1f993ca859db50f757dc12a2f852e6d5c37d221c477daa3378d31f7 }


condition:
	$a0
}