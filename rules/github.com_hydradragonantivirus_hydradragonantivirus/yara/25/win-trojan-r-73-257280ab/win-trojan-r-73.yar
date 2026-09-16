rule Win_Trojan_R_73
{
strings:
	$a0 = { 402e8996e4032e8986e603b8004233c999cd21b4408d96e203b91800cd21e82800b43ecd21e831 }


condition:
	$a0
}