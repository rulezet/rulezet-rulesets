rule Win_Trojan_Hidenowt_1
{
strings:
	$a0 = { 9c5825fff8509de421a21801b0ffe621e85301c1f8e5 }


condition:
	$a0
}