rule Win_Trojan_ProtoT_1
{
strings:
	$a0 = { 5756505351523d004b750d2e8c1e29052e89162b05eb }


condition:
	$a0
}