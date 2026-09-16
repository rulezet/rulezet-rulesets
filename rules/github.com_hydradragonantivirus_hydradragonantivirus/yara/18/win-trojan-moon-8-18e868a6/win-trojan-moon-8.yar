rule Win_Trojan_Moon_8
{
strings:
	$a0 = { 78636861742e636f6d6d616e6428226463[0-16]5d202b22202f746d702f6e6f6f6d6d2e6f64742229 }


condition:
	$a0
}