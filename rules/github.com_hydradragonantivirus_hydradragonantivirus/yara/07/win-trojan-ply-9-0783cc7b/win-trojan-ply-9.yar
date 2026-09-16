rule Win_Trojan_Ply_9
{
strings:
	$a0 = { 13e86f09b80001e8bb1190fb90e9f711b82020be212e9003f0bf352ee88e1105e2dd90cd2fe9 }


condition:
	$a0
}