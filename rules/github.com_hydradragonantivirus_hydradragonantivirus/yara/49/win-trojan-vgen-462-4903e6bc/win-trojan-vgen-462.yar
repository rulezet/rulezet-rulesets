rule Win_Trojan_VGEN_462
{
strings:
	$a0 = { cd21b001b435cd2106583d70007516b003b435cd2106583d70007509b42ccd2180fa0d7f04b082 }


condition:
	$a0
}