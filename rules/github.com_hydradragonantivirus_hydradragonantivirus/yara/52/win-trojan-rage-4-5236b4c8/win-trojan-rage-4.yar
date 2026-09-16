rule Win_Trojan_Rage_4
{
strings:
	$a0 = { 018a24518ac8d2c4598824fec046 }


condition:
	$a0
}