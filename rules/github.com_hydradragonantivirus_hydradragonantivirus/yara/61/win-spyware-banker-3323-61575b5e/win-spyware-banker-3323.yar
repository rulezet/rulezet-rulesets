rule Win_Spyware_Banker_3323
{
strings:
	$a0 = { 630c71c659c7206965480f4ac9b59d8571baca21af497ad475df2cff3404f0140912a72632272f391a6ec5b38a94b39b6eeeaa9f7a1c4e507f0ab9bff4fb8a10b83701d11b27 }


condition:
	$a0
}