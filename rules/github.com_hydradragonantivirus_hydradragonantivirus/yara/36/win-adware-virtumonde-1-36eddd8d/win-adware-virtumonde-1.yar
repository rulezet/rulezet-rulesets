rule Win_Adware_Virtumonde_1
{
strings:
	$a0 = { e800000000810424????????83ec046764a10000890424676489260000b9000000104975fd3129e1ad }


condition:
	$a0
}