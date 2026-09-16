rule Win_Trojan_VGEN_38
{
strings:
	$a0 = { 09ba6301cd21b8140cc1e8048ccb03d88ec3b9320051b43c33c9ba5b01cd2193b92f00ba930153bb000150e5402501 }


condition:
	$a0
}