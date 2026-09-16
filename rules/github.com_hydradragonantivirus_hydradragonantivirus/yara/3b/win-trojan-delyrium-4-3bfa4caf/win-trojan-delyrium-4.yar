rule Win_Trojan_Delyrium_4
{
strings:
	$a0 = { 4d4bcd217203e929015e568bfe33c0 }


condition:
	$a0
}