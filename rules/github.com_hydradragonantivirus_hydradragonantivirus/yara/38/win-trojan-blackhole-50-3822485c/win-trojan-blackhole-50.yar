rule Win_Trojan_Blackhole_50
{
strings:
	$a0 = { 622a6d5b22666c222b226f6f222b2272225d2864642f64293b0d0a096b3d762a }


condition:
	$a0
}