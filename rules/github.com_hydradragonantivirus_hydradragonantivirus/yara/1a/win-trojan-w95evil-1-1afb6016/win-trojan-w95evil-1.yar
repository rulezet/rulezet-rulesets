rule Win_Trojan_W95EVIL_1
{
strings:
	$a0 = { 03430089850a03430033c0be3c00f7bf66ad050000f7bf96ad3d504500000f857b0200008b }


condition:
	$a0
}