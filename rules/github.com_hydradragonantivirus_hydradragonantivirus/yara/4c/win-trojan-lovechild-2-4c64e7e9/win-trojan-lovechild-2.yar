rule Win_Trojan_LoveChild_2
{
strings:
	$a0 = { 33c08ed88ed0bc007cfbcd1248a31304b106d3e02dc007be4c00bf057dfca5a58ec0b9be018bf48bfc0e1ff3a406b8357c50cb33c0cd1333c08ec0b80102 }


condition:
	$a0
}