rule Win_Trojan_Chameleon_3
{
strings:
	$a0 = { 01b971e5b8dcd0f933ed306b00f5f8909047e2f6 }


condition:
	$a0
}