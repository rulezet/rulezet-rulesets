rule Win_Trojan_Lazarus_2
{
strings:
	$a0 = { 0103d6b80325cd210e07bf7202b98908cc47e2fceb052680358ccf }


condition:
	$a0
}