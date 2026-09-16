rule Win_Trojan_Magistr_3
{
strings:
	$a0 = { a1000083ec048904248bc46467a30000b800000000 }


condition:
	$a0
}