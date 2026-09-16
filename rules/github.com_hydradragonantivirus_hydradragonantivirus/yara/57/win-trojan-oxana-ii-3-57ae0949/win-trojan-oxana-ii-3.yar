rule Win_Trojan_Oxana_II_3
{
strings:
	$a0 = { ba0001b9330390b440cd2132c0e80801ba4304b91a00b440cd21b801578b1637048b0e390480f1 }


condition:
	$a0
}