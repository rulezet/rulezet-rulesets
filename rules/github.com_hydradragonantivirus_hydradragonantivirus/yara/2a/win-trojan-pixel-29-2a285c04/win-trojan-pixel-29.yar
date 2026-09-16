rule Win_Trojan_Pixel_29
{
strings:
	$a0 = { 03b9ffffb43fcd210553032ea311013e813e55035353742133c98bd12e8b1e1301b80042cd21 }


condition:
	$a0
}