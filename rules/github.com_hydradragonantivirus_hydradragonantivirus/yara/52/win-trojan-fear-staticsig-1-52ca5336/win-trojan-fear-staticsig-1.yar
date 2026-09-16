rule Win_Trojan_Fear_staticsig_1
{
strings:
	$a0 = { 5152cbfcbf000106570e1fbe9402a4a550ba300bb41acd21b82435cd210653ba5c02b82425cd21 }


condition:
	$a0
}