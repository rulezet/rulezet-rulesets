rule Win_Trojan_Khizhnjak_12
{
strings:
	$a0 = { 25ba1001b9ee0190b440cd21721833c933d2b80042cd21720dbafd02b90300b440cd217201 }


condition:
	$a0
}