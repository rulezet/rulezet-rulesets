rule Win_Trojan_TDSS_22
{
strings:
	$a0 = { e8e5ffffff558bec81ec4300000081ec3d00000053568b7508f6460c01570f84 }


condition:
	$a0
}