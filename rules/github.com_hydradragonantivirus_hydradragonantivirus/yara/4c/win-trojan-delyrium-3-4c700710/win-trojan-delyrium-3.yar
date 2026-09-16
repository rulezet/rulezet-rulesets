rule Win_Trojan_Delyrium_3
{
strings:
	$a0 = { 4d4bcd217203e929015e568bfe33c0501fc4064c002e8984dc }


condition:
	$a0
}