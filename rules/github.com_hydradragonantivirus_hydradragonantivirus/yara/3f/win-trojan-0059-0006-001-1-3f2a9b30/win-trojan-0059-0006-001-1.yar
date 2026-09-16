rule Win_Trojan__0059_0006_001_1
{
strings:
	$a0 = { 21b80042e84000b440b90400ba2003cd21b801572e8b1612032e8b0e100380e1e0fec1cd21 }


condition:
	$a0
}