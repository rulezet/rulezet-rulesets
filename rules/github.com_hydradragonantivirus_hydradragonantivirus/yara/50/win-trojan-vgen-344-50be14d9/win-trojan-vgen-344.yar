rule Win_Trojan_VGEN_344
{
strings:
	$a0 = { b944052e80340046e2f98cd82ea34d05a12c008ec0bf0000b001b96410fcf2ae47061f8bf70e07bfc904e86603 }


condition:
	$a0
}