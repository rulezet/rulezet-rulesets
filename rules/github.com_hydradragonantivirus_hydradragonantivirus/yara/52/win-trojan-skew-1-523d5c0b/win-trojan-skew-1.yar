rule Win_Trojan_Skew_1
{
strings:
	$a0 = { a30701b910002bcab440ba0001e881ffba0001b9b901b440e876ff33d233c9b80142e86cffb108 }


condition:
	$a0
}