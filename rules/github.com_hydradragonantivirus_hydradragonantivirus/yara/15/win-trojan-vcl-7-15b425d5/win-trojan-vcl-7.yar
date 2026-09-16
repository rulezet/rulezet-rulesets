rule Win_Trojan_Vcl_7
{
strings:
	$a0 = { ba4559b801facd16e800005d555d81ed????c686????2d8bc505????50eb00 }


condition:
	$a0
}