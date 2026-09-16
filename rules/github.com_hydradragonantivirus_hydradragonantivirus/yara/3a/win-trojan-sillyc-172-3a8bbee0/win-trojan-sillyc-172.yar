rule Win_Trojan_SillyC_172
{
strings:
	$a0 = { 0300c604e989440189f2b9410129cab440cd21b8004233c999cd2189f2b90300b440cd218b4c19 }


condition:
	$a0
}