rule Win_Trojan_Stoned_60
{
strings:
	$a0 = { 33ff33f648b106a31304d3e08ec087064e00a3447db8da0087064c00a3427d0e1fb90002f3 }


condition:
	$a0
}