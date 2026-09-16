rule Win_Trojan_Payback_1
{
strings:
	$a0 = { c08ed88ed0bcfefffb1eff0e1304cd12b10ad3c8c41e4c00891eba7d8c06bc7dc7064c008d00a34e008ec033ffbe }


condition:
	$a0
}