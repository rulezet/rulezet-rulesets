rule Win_Trojan_Risin_1
{
strings:
	$a0 = { 1e066a20070e1f33f626803c60741f33ffb90d01fcf3a4061fb82135cd21891e0d018c060f01ba5900b82125cd2107 }


condition:
	$a0
}