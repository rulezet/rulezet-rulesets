rule Win_Trojan_V_71
{
strings:
	$a0 = { 0b00b8003d33d21e8edacd2104011fbb1e00e84f02b82a03b300ba4701eb4701f98fd34b8dd3f8 }


condition:
	$a0
}