rule Win_Trojan_Destructor_4
{
strings:
	$a0 = { ffb80143e8fcfeb8023de8f6fe7229 }


condition:
	$a0
}