rule Win_Trojan_Rabbit_3
{
strings:
	$a0 = { 1a00fece890eb0018916b201b80103cdf17212b40333dbb90100b600cdf17205c606b4010107 }


condition:
	$a0
}