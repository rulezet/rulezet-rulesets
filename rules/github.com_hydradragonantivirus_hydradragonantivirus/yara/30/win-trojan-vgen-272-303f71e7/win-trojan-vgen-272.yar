rule Win_Trojan_VGEN_272
{
strings:
	$a0 = { 35cd21ba8d01b42506cd211f6a00079c8d170e06cd0126ff2e840060545d1e06c57610817c01ff2e7539817cfecd }


condition:
	$a0
}