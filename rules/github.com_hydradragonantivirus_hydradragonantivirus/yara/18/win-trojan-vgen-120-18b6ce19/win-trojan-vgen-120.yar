rule Win_Trojan_VGEN_120
{
strings:
	$a0 = { 89db89ff83e5ff83cb0089f689db89ff83c20083ce0089c089db89c983cb0083c20089c989db89d283e5ff83ce00 }


condition:
	$a0
}