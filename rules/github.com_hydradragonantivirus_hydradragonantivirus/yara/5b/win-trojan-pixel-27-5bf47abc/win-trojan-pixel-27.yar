rule Win_Trojan_Pixel_27
{
strings:
	$a0 = { 03b9ffffb43fcd21054e032ea311013e813e50034956742133c98bd12e8b1e1301b80042cd21 }


condition:
	$a0
}