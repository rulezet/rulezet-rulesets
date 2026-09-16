rule Win_Trojan_Troi_5
{
strings:
	$a0 = { ebb99c80fcfc7504b4559dcf5053515256571e0683ec28 }


condition:
	$a0
}