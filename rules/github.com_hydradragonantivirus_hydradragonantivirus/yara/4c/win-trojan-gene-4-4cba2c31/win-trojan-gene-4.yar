rule Win_Trojan_Gene_4
{
strings:
	$a0 = { 7252b8023dba9e00cd2193b80057cd215152b440ba0001b90b00cd21fe06c9027504fe06c902 }


condition:
	$a0
}