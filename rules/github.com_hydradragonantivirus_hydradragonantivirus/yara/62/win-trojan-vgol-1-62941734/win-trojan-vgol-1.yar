rule Win_Trojan_VGOL_1
{
strings:
	$a0 = { b440b9e60631d2e825003de606721529c931d2b80042e81600b440b91c00bae606e80b0059 }


condition:
	$a0
}