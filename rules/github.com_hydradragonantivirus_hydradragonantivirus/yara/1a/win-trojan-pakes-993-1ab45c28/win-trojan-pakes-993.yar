rule Win_Trojan_Pakes_993
{
strings:
	$a0 = { 60bf003140005733c00573796e63ab05 }


condition:
	$a0
}