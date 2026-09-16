rule Win_Trojan_Shanghai_II_3
{
strings:
	$a0 = { 34431e00f20c27150070f84011002a2e2a00434f4dd4455845909090e9af043500fcbf0001be1b0101deb90300f3 }


condition:
	$a0
}