rule Win_Trojan_Pardona_1
{
strings:
	$a0 = { 33c98bd08bc3e84df7ffff8bd68b4304e86f0200008bc3e8a8d2ffff6a005756e86fe1ffff56e8b1e1ffff33c05a5959648910eb18e9c2d4ffff8b45f8e812dcffff50e894e1ffffe867d6ffff }


condition:
	$a0
}