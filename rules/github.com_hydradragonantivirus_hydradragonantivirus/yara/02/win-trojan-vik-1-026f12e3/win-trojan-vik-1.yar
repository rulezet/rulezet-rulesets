rule Win_Trojan_Vik_1
{
strings:
	$a0 = { b8ddf0cd213c5074698b0e02002bc08ed8c4064c00bfd4022e89052e8c4502beb207ad8bd0ad3bd173068b143bd172 }


condition:
	$a0
}