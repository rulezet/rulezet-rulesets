rule Win_Trojan_Hero_1
{
strings:
	$a0 = { 84850210061eb4ffcd2180fc0074 }


condition:
	$a0
}