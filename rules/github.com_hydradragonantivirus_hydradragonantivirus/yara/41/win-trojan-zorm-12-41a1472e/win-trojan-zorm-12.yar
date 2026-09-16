rule Win_Trojan_Zorm_12
{
strings:
	$a0 = { a5a5a5a5b41a8d965f03cd21b44e8d963703b90700cd217303e95b01b8023d8d967d03cd2193b43fb91c008d964303cd21 }


condition:
	$a0
}