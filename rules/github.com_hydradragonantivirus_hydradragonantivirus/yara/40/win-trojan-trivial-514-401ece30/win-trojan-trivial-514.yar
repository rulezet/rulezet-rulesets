rule Win_Trojan_Trivial_514
{
strings:
	$a0 = { b44e33c9ba8601cd217239b8003dba9e00cd2193b43fb90400ba8c01cd21b43ecd21803e8f01027504b44febd5 }


condition:
	$a0
}