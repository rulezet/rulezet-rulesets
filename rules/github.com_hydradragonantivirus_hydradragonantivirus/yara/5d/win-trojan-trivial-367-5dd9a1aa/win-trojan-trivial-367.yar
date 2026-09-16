rule Win_Trojan_Trivial_367
{
strings:
	$a0 = { 33c98d164d01cd21723bb8023dba9e00cd2193b43fb904008d165301cd21803e5601617508b43ecd21b44febd332 }


condition:
	$a0
}