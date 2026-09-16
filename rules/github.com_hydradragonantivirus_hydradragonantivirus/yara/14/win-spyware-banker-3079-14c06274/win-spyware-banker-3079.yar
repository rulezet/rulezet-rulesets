rule Win_Spyware_Banker_3079
{
strings:
	$a0 = { 3fff768f9f0abb737537ab62b580fcd4641cfa9d2cec5b5ccebc9bf287772fd2832fdffc5ae6e31c0e2ff609fcbf087534d3afdee7e2e302a4bb41282d76 }


condition:
	$a0
}