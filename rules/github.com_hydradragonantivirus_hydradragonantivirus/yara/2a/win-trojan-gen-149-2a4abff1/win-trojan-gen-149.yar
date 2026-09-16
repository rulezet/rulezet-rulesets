rule Win_Trojan_Gen_149
{
strings:
	$a0 = { fe3b46fa75cdbf24011e579a56054c009a91024c0089ec5dc33354686973206973205b467269 }


condition:
	$a0
}