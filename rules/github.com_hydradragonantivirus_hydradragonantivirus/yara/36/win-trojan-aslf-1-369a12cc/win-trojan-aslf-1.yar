rule Win_Trojan_Aslf_1
{
strings:
	$a0 = { 0e1304a11304c1e0068ec01e560668380033ff89c1f3a4cbc4064c002ea37e002e8c068000c7 }


condition:
	$a0
}