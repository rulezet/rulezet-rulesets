rule Win_Trojan_KillCMOS_3
{
strings:
	$a0 = { b805e0cd16b807e0cd1650558becc7460200f05d0733ffb8c800b9fffff3abb00150e670e47132c0e67158fec03c8075f0c3 }


condition:
	$a0
}