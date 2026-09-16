rule Win_Trojan_Gene_1
{
strings:
	$a0 = { cd217252b8023dba9e00cd2193b80057cd215152b440ba0001b90b00cd21fe06c5027504fe06c5 }


condition:
	$a0
}